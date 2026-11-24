<?php

namespace Kanboard\Plugin\Gumshoe\GitHub;

use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Inventory\ComposerLock;
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

    /**
     * Files carry InventoryStore's parse input and, for npm and pnpm, registryConfig.
     * Registry config is a registry/scope-to-host map when known, or 'unknown'.
     */
    public function read(array $owner, #[\SensitiveParameter] array $repo, ?string $jobRef = null): array
    {
        $scan = [
            'outcome' => 'partial', 'treeComplete' => false, 'headSha' => null, 'treeSha' => null,
            'files' => [], 'retryAt' => null,
        ];
        $login = strtolower($owner['login']);
        $name = $repo['name'];
        $branch = $repo['default_branch'] ?? '';
        if ($branch === '' || !preg_match('/\A[a-z0-9][a-z0-9-]{0,38}\z/', $login)
            || !preg_match('/\A[a-zA-Z0-9_.-]{1,100}\z/', $name) || in_array($name, ['.', '..'], true)) {
            return $scan;
        }

        $base = 'https://api.github.com/repos/'.$login.'/'.$name;
        try {
            $response = $this->client->send(new Request('gh.branch', $base.'/branches/'.rawurlencode($branch), $login), $jobRef);
            $scan['retryAt'] = $response->retryAt;
            if ($response->status === 409) {
                return array_replace($scan, ['outcome' => 'no_lockfile', 'treeComplete' => true]);
            }
            if ($response->status !== 200) {
                return $this->failedRead($scan, $response->status);
            }

            $commit = json_decode($response->body)->commit ?? null;
            $head = $commit->sha ?? null;
            $tree = $commit->commit->tree->sha ?? null;
            if (!self::isSha($head) || !self::isSha($tree)) {
                return $scan;
            }

            $scan['headSha'] = $head;
            $scan['treeSha'] = $tree;
            if ($scan['retryAt'] !== null) {
                return $scan;
            }
            $response = $this->client->send(new Request('gh.tree', $base.'/git/trees/'.$tree.'?recursive=1', $login), $jobRef);
            $scan['retryAt'] = $response->retryAt;
            if ($response->status !== 200) {
                return $this->failedRead($scan, $response->status);
            }
        } catch (HttpFailure $failure) {
            return $this->failedRead($scan, $failure->status);
        }

        $document = json_decode($response->body);
        if (!is_array($document->tree ?? null)) {
            return $scan;
        }

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
            if ($filename === '.npmrc') {
                $configs[$path] = $entry;
            } else {
                $files[$path] = [$entry, $kind];
            }
        }

        ksort($files, SORT_STRING);
        $scan['treeComplete'] = $treeComplete && count($files) <= Limits::MAX_REPO_LOCKFILES;
        $complete = $scan['treeComplete'];
        $seenRows = 0;
        $registryCache = [];
        foreach (array_slice($files, 0, Limits::MAX_REPO_LOCKFILES, true) as $path => [$entry, $kind]) {
            if ($scan['retryAt'] !== null) {
                $scan['treeComplete'] = $complete = false;
                break;
            }
            if ($seenRows === Limits::MAX_REPO_DEPS) {
                $result = new ParseResult([], 'too_many');
            } else {
                [$body, $status, $scan['retryAt']] = $this->blob($base, $login, $entry, $jobRef);
                $parser = self::PARSERS[$kind];
                $result = $body === null ? new ParseResult([], $status) : $parser::parse($body, new Limits($seenRows));
                $seenRows += count($result->deps);
                unset($body);
            }

            $file = [
                'path' => $path, 'blob_sha' => $entry->sha, 'kind' => $kind, 'parser_version' => 1, 'result' => $result,
            ];
            $complete = $complete && $result->status === 'ok';
            if ($kind === 'npm' || $kind === 'pnpm') {
                $config = $treeComplete
                    ? $this->registryConfig($base, $login, $path, $configs, $registryCache, $scan['retryAt'], $jobRef)
                    : 'unknown';
                $file['registryConfig'] = $config;
                $complete = $complete && $config !== 'unknown';
            }
            $scan['files'][] = $file;
        }

        $scan['outcome'] = $complete ? ($files === [] ? 'no_lockfile' : 'complete') : 'partial';
        return $scan;
    }

    private function failedRead(array $scan, ?int $status): array
    {
        if (in_array($status, [401, 403, 404], true)) {
            $scan['outcome'] = 'inaccessible';
        }
        return $scan;
    }

    /** @return array{?string, string, ?int} */
    private function blob(#[\SensitiveParameter] string $base, string $login, stdClass $entry, ?string $jobRef): array
    {
        if (($entry->type ?? null) !== 'blob' || !in_array($entry->mode ?? null, ['100644', '100755'], true)) {
            return [null, 'unsupported', null];
        }
        if (is_int($entry->size ?? null) && $entry->size > Limits::MAX_FILE_BYTES) {
            return [null, 'too_large', null];
        }

        $request = new Request(
            'gh.blob', $base.'/git/blobs/'.$entry->sha, $login,
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

    private function registryConfig(
        #[\SensitiveParameter] string $base,
        string $login,
        #[\SensitiveParameter] string $path,
        #[\SensitiveParameter] array $configs,
        #[\SensitiveParameter] array &$cache,
        ?int &$retryAt,
        ?string $jobRef,
    ): array|string {
        $directory = dirname($path);
        $candidates = $directory === '.' ? ['.npmrc'] : ['.npmrc', $directory.'/.npmrc'];
        $config = [];
        foreach ($candidates as $candidate) {
            if (!isset($configs[$candidate])) {
                continue;
            }
            if (!array_key_exists($candidate, $cache)) {
                if ($retryAt !== null) {
                    return 'unknown';
                }
                [$body, , $retryAt] = $this->blob($base, $login, $configs[$candidate], $jobRef);
                $cache[$candidate] = $body === null ? null : self::registryHosts($body);
            }
            if ($cache[$candidate] === null) {
                return 'unknown';
            }
            $config = array_replace($config, $cache[$candidate]);
        }
        return $config;
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
