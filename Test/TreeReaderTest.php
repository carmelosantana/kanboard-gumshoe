<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\GitHub\TreeReader;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Inventory\Limits;
use Kanboard\Plugin\Gumshoe\Secrets\VaultTokenSource;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeVaultSecrets;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/Fakes/FakeVaultSecrets.php';

final class TreeReaderTest extends TestCase
{
    private const BASE = 'https://api.github.com/repos/symfony/yaml';
    private const HEAD = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa';
    private const TREE = 'bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb';
    private const OWNER = ['login' => 'symfony'];
    private const REPO = ['name' => 'yaml', 'default_branch' => 'feature/stable'];

    public function testResolvesDefaultBranchAndFetchesOnlySupportedPathsWithRawMediaType(): void
    {
        $entries = [
            $this->entry('node_modules/package-lock.json', 1),
            $this->entry('packages/vendor/composer.lock', 2),
            $this->entry('packages/tool/deep/package-lock.json', 3),
            $this->entry('.github/workflows/ci.yml', 4),
            $this->entry('composer.lock', 5),
        ];
        [$reader, $transport, $vault] = $this->reader([
            $this->branch(),
            $this->tree($entries),
            new Response(200, [], 'jobs: {}'),
            new Response(200, [], '{"packages":[]}'),
            new Response(200, [], '{"lockfileVersion":3,"packages":{}}'),
        ]);

        $scan = $reader->read(self::OWNER, self::REPO, 'inventory');
        self::assertSame('complete', $scan['outcome']);
        self::assertTrue($scan['treeComplete']);
        self::assertSame(self::HEAD, $scan['headSha']);
        self::assertSame(self::TREE, $scan['treeSha']);
        self::assertSame(['.github/workflows/ci.yml', 'composer.lock', 'packages/tool/deep/package-lock.json'],
            array_column($scan['files'], 'path'));
        self::assertSame([
            self::BASE.'/branches/feature%2Fstable', self::BASE.'/git/trees/'.self::TREE.'?recursive=1',
            ...array_map(static fn ($entry) => self::BASE.'/git/blobs/'.$entry['sha'], [$entries[3], $entries[4], $entries[2]]),
        ], array_column($transport->requests, 'url'));
        foreach (array_slice($transport->requests, 2) as $request) {
            self::assertSame('application/vnd.github.raw+json', $request->headers['Accept']);
        }
        self::assertSame([true, true, true, true, true], $transport->authenticated);
        self::assertSame([['Gumshoe', 'vault://17/token', 'inventory']], $vault->reads);
    }

    public function testEmptyAndInaccessibleBranchesAndManifestOnlyTreeHaveDistinctOutcomes(): void
    {
        foreach ([409 => 'no_lockfile', 404 => 'inaccessible', 403 => 'inaccessible', 503 => 'partial'] as $code => $outcome) {
            [$reader, $transport] = $this->reader([new Response($code)]);
            $scan = $reader->read(self::OWNER, self::REPO);
            self::assertSame($outcome, $scan['outcome']);
            self::assertSame($code === 409, $scan['treeComplete']);
            self::assertCount(1, $transport->requests);
        }
        [$reader, $transport] = $this->reader([
            $this->branch(), $this->tree([$this->entry('composer.json', 1), $this->entry('example/package.json', 2)]),
        ]);
        $scan = $reader->read(self::OWNER, self::REPO);
        self::assertSame('no_lockfile', $scan['outcome']);
        self::assertTrue($scan['treeComplete']);
        self::assertCount(2, $transport->requests);
    }

    public function testSortsBeforeApplyingTheFiftyFileCap(): void
    {
        $workflow = $this->entry('.github/workflows/ci.yml', 51);
        $entries = [];
        for ($i = 0; $i < 51; ++$i) {
            $entries[] = $this->entry(sprintf('%02d/composer.lock', $i), $i);
        }
        [$reader, $transport] = $this->reader([
            $this->branch(), $this->tree([$workflow, ...array_reverse($entries)]),
            ...array_fill(0, 50, new Response(200, [], '{"packages":[]}')),
        ]);
        $scan = $reader->read(self::OWNER, self::REPO);
        self::assertSame('partial', $scan['outcome']);
        self::assertFalse($scan['treeComplete']);
        self::assertSame(array_column(array_slice($entries, 0, 50), 'path'), array_column($scan['files'], 'path'));
        self::assertCount(52, $transport->requests);
        self::assertNotContains(self::BASE.'/git/blobs/'.$entries[50]['sha'], array_column($transport->requests, 'url'));
        self::assertNotContains(self::BASE.'/git/blobs/'.$workflow['sha'], array_column($transport->requests, 'url'));
    }

    public function testRegistryConfigUsesOnlyHostsAndInheritsRootEntries(): void
    {
        $entries = [
            $this->entry('.npmrc', 1),
            $this->entry('packages/tool/.npmrc', 2),
            $this->entry('packages/tool/pnpm-lock.yaml', 3),
            $this->entry('package-lock.json', 4),
        ];
        [$reader, $transport] = $this->reader([
            $this->branch(), $this->tree($entries),
            static fn () => new Response(200, [], '{"lockfileVersion":3,"packages":{}}'),
            new Response(200, [], "registry = https://registry.npmjs.org/\r\n@npmcli:registry=https://example.org/npm/\r\n"),
            new Response(200, [], "lockfileVersion: '9.0'"),
            new Response(200, [], "@npmcli:registry=https://packages.example.net/path?ignored=1\n"),
        ]);
        $scan = $reader->read(self::OWNER, self::REPO);
        self::assertSame('complete', $scan['outcome']);
        self::assertSame(['registry' => 'registry.npmjs.org', '@npmcli' => 'example.org'], $scan['files'][0]['registryConfig']);
        self::assertSame(['registry' => 'registry.npmjs.org', '@npmcli' => 'packages.example.net'], $scan['files'][1]['registryConfig']);
        self::assertCount(6, $transport->requests);
    }

    public function testIncompleteTreeAndUnreadableConfigCannotGiveRegistryEvidence(): void
    {
        $lock = $this->entry('package-lock.json', 1);
        $config = $this->entry('.npmrc', 2);
        foreach ([
            [true, $config, null],
            [false, array_replace($config, ['size' => Limits::MAX_FILE_BYTES + 1]), null],
            [false, $config, new Response(404)],
            [false, $config, new Response(200, [], 'registry=${NPM_REGISTRY}')],
            [false, $config, new Response(200, [], 'registry=https://example.org\@registry.npmjs.org/')],
            [false, $config, new Response(200, [], 'registry=https://example.org;@registry.npmjs.org/')],
        ] as [$truncated, $configEntry, $configResponse]) {
            [$reader, $transport] = $this->reader(array_filter([
                $this->branch(), $this->tree([$lock, $configEntry], $truncated),
                new Response(200, [], '{"lockfileVersion":3,"packages":{}}'), $configResponse,
            ]));
            $scan = $reader->read(self::OWNER, self::REPO);
            self::assertSame('partial', $scan['outcome']);
            self::assertSame(!$truncated, $scan['treeComplete']);
            self::assertSame('unknown', $scan['files'][0]['registryConfig']);
            self::assertCount($configResponse === null ? 3 : 4, $transport->requests);
        }
    }

    public function testRegistryParserRejectsAnEightMiBBodyUnderTheScanMemoryLimit(): void
    {
        $script = <<<'PHP'
            $loader = require $argv[1].'/vendor/autoload.php';
            $loader->addPsr4('Kanboard\\Plugin\\Gumshoe\\', $argv[1]);
            $parse = new ReflectionMethod(Kanboard\Plugin\Gumshoe\GitHub\TreeReader::class, 'registryHosts');
            $hosts = $parse->invoke(null, str_repeat("\n", 8 * 1024 * 1024));
            echo $hosts === null ? 'unknown' : 'known';
            PHP;
        $process = proc_open(
            [PHP_BINARY, '-d', 'memory_limit=128M', '-r', $script, dirname(__DIR__)],
            [1 => ['pipe', 'w'], 2 => ['redirect', 1]],
            $pipes,
        );
        self::assertIsResource($process);
        $output = stream_get_contents($pipes[1]);
        fclose($pipes[1]);
        self::assertSame(0, proc_close($process), $output);
        self::assertSame('unknown', $output);
    }

    public function testOversizeRegistryConfigIsSkippedBeforeFetchingAndTheNextRepoIsProcessed(): void
    {
        $lock = $this->entry('package-lock.json', 1);
        $config = array_replace($this->entry('.npmrc', 2), ['size' => 64 * 1024 + 1]);
        $npm = new Response(200, [], '{"lockfileVersion":3,"packages":{}}');
        [$reader, $transport] = $this->reader([
            $this->branch(), $this->tree([$lock, $config]), $npm,
            $this->branch(), $this->tree([$lock]), $npm,
        ]);

        $first = $reader->read(self::OWNER, self::REPO);
        $second = $reader->read(self::OWNER, ['name' => 'console', 'default_branch' => 'main']);
        self::assertSame('partial', $first['outcome']);
        self::assertSame('unknown', $first['files'][0]['registryConfig']);
        self::assertSame('complete', $second['outcome']);
        self::assertSame([], $second['files'][0]['registryConfig']);
        self::assertCount(6, $transport->requests);
        self::assertNotContains(self::BASE.'/git/blobs/'.$config['sha'], array_column($transport->requests, 'url'));
    }

    public function testRegistryConfigEnforcesBodyAndLineLimits(): void
    {
        $registry = 'registry=https://registry.npmjs.org/';
        $atByteLimit = $registry.str_repeat("\n".str_repeat(' ', 4095), 15);
        $atByteLimit .= "\n".str_repeat(' ', 64 * 1024 - strlen($atByteLimit) - 1);
        $known = ['registry' => 'registry.npmjs.org'];
        $cases = [
            [$atByteLimit, $known],
            [$atByteLimit.' ', 'unknown'],
            [str_repeat("\r\n", 1999).$registry."\r\n", $known],
            [str_repeat("\r\n", 2000).$registry, 'unknown'],
            [$registry."\r".str_repeat('#', 4096), $known],
            [$registry."\r".str_repeat('#', 4097), 'unknown'],
            ["\xef\xbb\xbf".$registry."\rignored=value\r".'@npmcli:registry=https://example.org/', $known + ['@npmcli' => 'example.org']],
        ];
        foreach ($cases as [$body, $expected]) {
            [$reader] = $this->reader([
                $this->branch(), $this->tree([$this->entry('package-lock.json', 1), $this->entry('.npmrc', 2)]),
                new Response(200, [], '{"lockfileVersion":3,"packages":{}}'),
                new Response(200, [], $body),
            ]);
            $scan = $reader->read(self::OWNER, self::REPO);
            self::assertSame($expected, $scan['files'][0]['registryConfig']);
        }
    }

    public function testOversizeBlobsReportPartialBeforeFetchAndAfterDecode(): void
    {
        $entries = [
            array_replace($this->entry('a/composer.lock', 1), ['size' => Limits::MAX_FILE_BYTES + 1]),
            $this->entry('b/composer.lock', 2),
        ];
        [$reader, $transport] = $this->reader([
            $this->branch(), $this->tree($entries),
            new Response(200, [], str_repeat(' ', Limits::MAX_FILE_BYTES + 1)),
        ]);
        $scan = $reader->read(self::OWNER, self::REPO);
        self::assertSame('partial', $scan['outcome']);
        self::assertSame(['too_large', 'too_large'], array_map(static fn ($file) => $file['result']->status, $scan['files']));
        self::assertCount(3, $transport->requests);
        self::assertSame(self::BASE.'/git/blobs/'.$entries[1]['sha'], $transport->requests[2]->url);
    }

    private function reader(array $responses): array
    {
        $transport = new FakeTransport($responses);
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of(bin2hex(random_bytes(16))));
        $tokens = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token');
        return [new TreeReader(new Client($transport, 'https://kanboard.example/', $tokens)), $transport, $vault];
    }

    private function entry(string $path, int $number): array
    {
        return ['path' => $path, 'sha' => sprintf('%040x', $number), 'type' => 'blob', 'mode' => '100644', 'size' => 0];
    }

    private function branch(): Response
    {
        return new Response(200, [], json_encode(['commit' => [
            'sha' => self::HEAD, 'commit' => ['tree' => ['sha' => self::TREE]],
        ]], JSON_THROW_ON_ERROR));
    }

    private function tree(array $entries, bool $truncated = false): Response
    {
        return new Response(200, [], json_encode(['tree' => $entries, 'truncated' => $truncated], JSON_THROW_ON_ERROR));
    }
}
