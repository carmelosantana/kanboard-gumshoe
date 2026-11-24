<?php

namespace Kanboard\Plugin\Gumshoe\GitHub;

use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Inventory\ComposerLock;
use Kanboard\Plugin\Gumshoe\Inventory\Dependency;
use Kanboard\Plugin\Gumshoe\Inventory\Limits;
use Kanboard\Plugin\Gumshoe\Inventory\NpmLock;
use Kanboard\Plugin\Gumshoe\Inventory\ParseResult;
use Kanboard\Plugin\Gumshoe\Inventory\PnpmLock;
use Kanboard\Plugin\Gumshoe\Inventory\Workflows;
use stdClass;

final class TreeReader
{
    private const PARSERS = [
        'composer' => ComposerLock::class,
        'npm' => NpmLock::class,
        'pnpm' => PnpmLock::class,
        'actions' => Workflows::class,
    ];
    private const LOCKFILES = [
        'composer.lock' => 'composer',
        'package-lock.json' => 'npm',
        'pnpm-lock.yaml' => 'pnpm',
    ];

    public function __construct(private readonly Client $client)
    {
    }

    public function read(array $owner, #[\SensitiveParameter] array $repo, ?string $jobRef = null): array
    {
        $slice = $this->readSlice($owner, $repo, null, $jobRef);
        return self::scan($slice['scan'], $slice['files']);
    }

    /**
     * Resume from a JSON-compatible checkpoint, including the index of the next file.
     * Return newly completed files and either the next checkpoint or the final scan.
     * Each step uses at most one Client request.
     */
    public function readSlice(
        array $owner,
        #[\SensitiveParameter] array $repo,
        #[\SensitiveParameter] ?array $state,
        ?string $jobRef = null,
        ?int $budget = null,
    ): array {
        $state ??= [
            'scan' => [
                'outcome' => 'partial', 'treeComplete' => false, 'headSha' => null, 'treeSha' => null, 'retryAt' => null,
            ],
            'entries' => null, 'configs' => [], 'registryCache' => [],
            'index' => 0, 'rows' => 0, 'parsed' => null,
        ];
        $scan = &$state['scan'];
        $files = [];
        $login = strtolower($owner['login']);
        $name = $repo['name'];
        $branch = $repo['default_branch'] ?? '';
        if ($branch === '' || !preg_match('/\A[a-z0-9][a-z0-9-]{0,38}\z/', $login)
            || !preg_match('/\A[a-zA-Z0-9_.-]{1,100}\z/', $name) || in_array($name, ['.', '..'], true)) {
            return ['scan' => $scan, 'state' => null, 'files' => []];
        }

        $base = 'https://api.github.com/repos/'.$login.'/'.$name;
        while ($budget === null || $budget-- > 0) {
            if ($scan['headSha'] === null || $state['entries'] === null) {
                if (!$this->readMetadata($base, $login, $branch, $state, $jobRef)) {
                    return ['scan' => $scan, 'state' => null, 'files' => $files];
                }
            } else {
                $file = $this->readFile($base, $login, $state, $jobRef);
                if ($file !== null) {
                    $files[] = $file;
                }
            }

            if ($state['entries'] !== null && $state['index'] === count($state['entries'])) {
                if ($scan['treeComplete'] && $scan['outcome'] !== 'partial') {
                    $scan['outcome'] = $state['index'] === 0 ? 'no_lockfile' : 'complete';
                }
                return ['scan' => $scan, 'state' => null, 'files' => $files];
            }
            if ($scan['retryAt'] !== null) {
                $scan['treeComplete'] = false;
                $scan['outcome'] = 'partial';
                return ['scan' => $scan, 'state' => null, 'files' => $files];
            }
        }

        return ['scan' => null, 'state' => $state, 'files' => $files];
    }

    /** Rebuild the inventory API's value objects from staged parsed results. */
    public static function scan(array $scan, array $files): array
    {
        foreach ($files as &$file) {
            $result = $file['result'];
            $file['result'] = new ParseResult(
                array_map(static fn (array $dep): Dependency => new Dependency(...$dep), $result['deps']),
                $result['status'],
            );
        }
        unset($file);
        return $scan + ['files' => $files];
    }

    private function readMetadata(
        #[\SensitiveParameter] string $base,
        string $login,
        #[\SensitiveParameter] string $branch,
        #[\SensitiveParameter] array &$state,
        ?string $jobRef,
    ): bool {
        $scan = &$state['scan'];
        $branchRequest = $scan['headSha'] === null;
        $request = $branchRequest
            ? new Request('gh.branch', $base.'/branches/'.rawurlencode($branch), $login)
            : new Request('gh.tree', $base.'/git/trees/'.$scan['treeSha'].'?recursive=1', $login);
        try {
            $response = $this->client->send($request, $jobRef);
        } catch (HttpFailure $failure) {
            $scan = $this->failedRead($scan, $failure->status);
            return false;
        }

        $scan['retryAt'] = $response->retryAt;
        if ($branchRequest && $response->status === 409) {
            $scan = array_replace($scan, ['outcome' => 'no_lockfile', 'treeComplete' => true]);
            return false;
        }
        if ($response->status !== 200) {
            $scan = $this->failedRead($scan, $response->status);
            return false;
        }

        $document = json_decode($response->body);
        if ($branchRequest) {
            $head = $document->commit->sha ?? null;
            $tree = $document->commit->commit->tree->sha ?? null;
            if (!self::isSha($head) || !self::isSha($tree)) {
                return false;
            }
            $scan['headSha'] = $head;
            $scan['treeSha'] = $tree;
            return true;
        }
        if (!is_array($document->tree ?? null)) {
            return false;
        }

        $this->selectEntries($document, $state);
        return true;
    }

    private function selectEntries(#[\SensitiveParameter] stdClass $document, #[\SensitiveParameter] array &$state): void
    {
        $treeComplete = ($document->truncated ?? null) === false;
        $files = [];
        $configs = [];
        $paths = [];
        foreach ($document->tree as $entry) {
            $path = $entry->path ?? null;
            if (!is_string($path) || $path === '' || isset($paths[$path])) {
                $treeComplete = false;
                continue;
            }
            $paths[$path] = true;
            if (preg_match('~(?:^|/)(?:node_modules|vendor)/~', $path)) {
                continue;
            }

            $filename = basename($path);
            $kind = self::LOCKFILES[$filename] ?? null;
            if (preg_match('~\A\.github/workflows/[^/]+\.ya?ml\z~', $path)) {
                $kind = 'actions';
            }
            if ($filename !== '.npmrc' && $kind === null) {
                continue;
            }
            if (($entry->type ?? null) === 'tree') {
                continue;
            }
            if (!self::isSha($entry->sha ?? null) || strlen($path) > 1024) {
                $treeComplete = false;
                continue;
            }

            $blob = ['sha' => $entry->sha, 'type' => $entry->type ?? null, 'mode' => $entry->mode ?? null,
                'size' => $entry->size ?? null];
            if ($filename === '.npmrc') {
                $configs[$path] = $blob;
            } else {
                $files[$path] = ['path' => $path, 'kind' => $kind, 'blob' => $blob];
            }
        }

        ksort($files, SORT_STRING);
        $state['scan']['treeComplete'] = $treeComplete && count($files) <= Limits::MAX_REPO_LOCKFILES;
        $state['scan']['outcome'] = $state['scan']['treeComplete'] ? 'complete' : 'partial';
        $state['entries'] = array_slice(array_values($files), 0, Limits::MAX_REPO_LOCKFILES);
        $state['registryKnown'] = $treeComplete;
        foreach ($state['entries'] as $entry) {
            if (in_array($entry['kind'], ['npm', 'pnpm'], true)) {
                foreach (self::configPaths($entry['path']) as $path) {
                    if (isset($configs[$path])) {
                        $state['configs'][$path] = $configs[$path];
                    }
                }
            }
        }
    }

    private function readFile(
        #[\SensitiveParameter] string $base,
        string $login,
        #[\SensitiveParameter] array &$state,
        ?string $jobRef,
    ): ?array {
        $entry = $state['entries'][$state['index']];
        $kind = $entry['kind'];
        $path = $entry['path'];
        $scan = &$state['scan'];
        $parsed = &$state['parsed'];
        $usedRequest = false;
        if ($parsed === null) {
            if ($state['rows'] === Limits::MAX_REPO_DEPS) {
                $result = new ParseResult([], 'too_many');
            } else {
                [$body, $status, $scan['retryAt']] = $this->blob($base, $login, $entry['blob'], $jobRef);
                $usedRequest = true;
                $parser = self::PARSERS[$kind];
                $result = $body === null ? new ParseResult([], $status) : $parser::parse($body, new Limits($state['rows']));
                $state['rows'] += count($result->deps);
            }
            $parsed = ['status' => $result->status, 'deps' => array_map(get_object_vars(...), $result->deps)];
        }

        $file = ['path' => $path, 'blob_sha' => $entry['blob']['sha'], 'kind' => $kind,
            'parser_version' => 1, 'result' => $parsed];
        if (in_array($kind, ['npm', 'pnpm'], true)) {
            $config = $state['registryKnown'] ? [] : 'unknown';
            if ($state['registryKnown']) {
                foreach (self::configPaths($path) as $candidate) {
                    if (!isset($state['configs'][$candidate])) {
                        continue;
                    }
                    if (!array_key_exists($candidate, $state['registryCache'])) {
                        if ($scan['retryAt'] !== null) {
                            $config = 'unknown';
                            break;
                        }
                        if ($usedRequest) {
                            return null;
                        }
                        [$body, , $scan['retryAt']] = $this->blob($base, $login, $state['configs'][$candidate], $jobRef);
                        $state['registryCache'][$candidate] = $body === null ? null : self::registryHosts($body);
                        $usedRequest = true;
                    }
                    $hosts = $state['registryCache'][$candidate];
                    if ($hosts === null) {
                        $config = 'unknown';
                        break;
                    }
                    $config = array_replace($config, $hosts);
                }
            }
            $file['registryConfig'] = $config;
            if ($config === 'unknown') {
                $scan['outcome'] = 'partial';
            }
        }
        if ($parsed['status'] !== 'ok') {
            $scan['outcome'] = 'partial';
        }

        $state['index']++;
        $parsed = null;
        return $file;
    }

    private static function configPaths(#[\SensitiveParameter] string $path): array
    {
        $directory = dirname($path);
        return $directory === '.' ? ['.npmrc'] : ['.npmrc', $directory.'/.npmrc'];
    }

    private function failedRead(array $scan, ?int $status): array
    {
        if (in_array($status, [401, 403, 404], true)) {
            $scan['outcome'] = 'inaccessible';
        }
        return $scan;
    }

    /** @return array{?string, string, ?int} */
    private function blob(#[\SensitiveParameter] string $base, string $login, array $entry, ?string $jobRef): array
    {
        if ($entry['type'] !== 'blob' || !in_array($entry['mode'], ['100644', '100755'], true)) {
            return [null, 'unsupported', null];
        }
        if (is_int($entry['size']) && $entry['size'] > Limits::MAX_FILE_BYTES) {
            return [null, 'too_large', null];
        }

        $request = new Request(
            'gh.blob', $base.'/git/blobs/'.$entry['sha'], $login,
            headers: ['Accept' => 'application/vnd.github.raw+json'],
        );
        try {
            $response = $this->client->send($request, $jobRef);
        } catch (HttpFailure $failure) {
            $status = in_array($failure->reason, ['wire_too_large', 'decoded_too_large'], true) ? 'too_large' : 'stale';
            return [null, $status, null];
        }
        if ($response->status !== 200) {
            return [null, 'stale', $response->retryAt];
        }
        if (strlen($response->body) > Limits::MAX_FILE_BYTES) {
            return [null, 'too_large', $response->retryAt];
        }
        return [$response->body, 'ok', $response->retryAt];
    }

    private static function registryHosts(#[\SensitiveParameter] string $contents): ?array
    {
        $contents = str_starts_with($contents, "\xef\xbb\xbf") ? substr($contents, 3) : $contents;
        $hosts = [];
        foreach (preg_split('/\r\n|\r|\n/', $contents) as $line) {
            if (!preg_match('/\A\s*((@[a-z0-9_.-]+):registry|registry)\s*(?==|\[|$)(.*)\z/i', $line, $assignment)) {
                continue;
            }
            $value = ltrim($assignment[3]);
            if (!str_starts_with($value, '=')) {
                return null;
            }

            $value = trim(preg_split('/\s+[;#]/', trim(substr($value, 1)), 2)[0]);
            if ($value !== '' && in_array($value[0], ['"', "'"], true) && str_ends_with($value, $value[0])) {
                $value = substr($value, 1, -1);
            }
            // Reject ambiguous URL/INI syntax before extracting a host.
            if (str_contains($value, '${') || str_contains($value, '\\') || preg_match('/[\x00-\x20\x7f;#"\']/', $value)) {
                return null;
            }
            $url = parse_url($value);
            $host = strtolower($url['host'] ?? '');
            if (!in_array(strtolower($url['scheme'] ?? ''), ['http', 'https'], true)
                || !preg_match('/\A[a-z0-9][a-z0-9.-]*\z/', $host)) {
                return null;
            }
            $hosts[strtolower($assignment[2] ?: 'registry')] = $host;
        }
        return $hosts;
    }

    private static function isSha(mixed $value): bool
    {
        return is_string($value) && preg_match('/\A(?:[a-f0-9]{40}|[a-f0-9]{64})\z/', $value) === 1;
    }
}
