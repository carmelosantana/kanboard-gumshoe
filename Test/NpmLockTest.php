<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Inventory\Limits;
use Kanboard\Plugin\Gumshoe\Inventory\NpmLock;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class NpmLockTest extends TestCase
{
    public function testV1WalksNestedDependencies(): void
    {
        $result = NpmLock::parse($this->fixture('lockfiles/package-lock.v1.json'), new Limits());

        self::assertSame('ok', $result->status);
        $nested = array_values(array_filter($result->deps, static fn ($dep) =>
            $dep->name === 'universal-user-agent' && $dep->version === '4.0.0'
        ));
        self::assertCount(3, $nested);
        self::assertSame('npm', $nested[0]->ecosystem);
        self::assertSame('npmjs', $nested[0]->registry_evidence);
        self::assertSame('package', $nested[0]->query_type);
        $byName = array_column($result->deps, null, 'name');
        self::assertSame('prod', $byName['@actions/core']->scope);
    }

    public function testV2ReadsPackagePathsAndKeepsDifferentVersions(): void
    {
        $result = NpmLock::parse(<<<'JSON'
            {
                "lockfileVersion":2,
                "packages":{
                    "":{"name":"example","version":"1.0.0"},
                    "node_modules/is-positive":{"version":"1.0.0","resolved":"https://registry.npmjs.org/is-positive/-/is-positive-1.0.0.tgz"},
                    "node_modules/lodash/node_modules/is-positive":{"version":"3.1.0","dev":true,"resolved":"https://registry.npmjs.org.example/is-positive/-/is-positive-3.1.0.tgz"},
                    "node_modules/lodash/node_modules/@types/node":{"version":"22.0.0"}
                },
                "dependencies":{"is-positive":{"version":"1.0.0"}}
            }
            JSON, new Limits());

        self::assertSame('ok', $result->status);
        self::assertSame(['is-positive', 'is-positive', '@types/node'], array_column($result->deps, 'name'));
        self::assertSame(['1.0.0', '3.1.0', '22.0.0'], array_column($result->deps, 'version'));
        self::assertSame(['prod', 'dev', 'prod'], array_column($result->deps, 'scope'));
        self::assertSame(['npmjs', null, null], array_column($result->deps, 'registry_evidence'));
    }

    public function testV1AndV3ResolveAliases(): void
    {
        $v1 = NpmLock::parse($this->fixture('lockfiles/package-lock.v1-alias.hand.json'), new Limits());
        $v3 = NpmLock::parse($this->fixture('lockfiles/package-lock.v3-alias.hand.json'), new Limits());

        self::assertSame('ok', $v1->status);
        self::assertSame('ok', $v3->status);
        self::assertSame(['string-width'], array_column($v1->deps, 'name'));
        self::assertSame(['4.2.3'], array_column($v1->deps, 'version'));
        self::assertSame(['string-width', 'string-width'], array_column($v3->deps, 'name'));
        self::assertSame(['5.1.2', '4.2.3'], array_column($v3->deps, 'version'));
    }

    public function testWorkspaceMemberKeepsScopeAndLinkDoesNotCreateARow(): void
    {
        $contents = $this->fixture('lockfiles/package-lock.v3-workspace.json');
        $result = NpmLock::parse($contents, new Limits());

        self::assertSame('ok', $result->status);
        self::assertSame(['arg', 'ws'], array_column($result->deps, 'name'));
        self::assertSame(['prod', 'prod'], array_column($result->deps, 'scope'));
        self::assertSame(['npmjs', null], array_column($result->deps, 'registry_evidence'));

        $workspace = json_decode($contents, false, 64, JSON_THROW_ON_ERROR);
        $workspace->packages->ws->dev = true;
        $result = NpmLock::parse(json_encode($workspace, JSON_THROW_ON_ERROR), new Limits());
        self::assertSame(['prod', 'dev'], array_column($result->deps, 'scope'));
    }

    public function testOverSizeLockfileReturnsNoRows(): void
    {
        $contents = gzdecode($this->fixture('hostile/package-lock-12MiB.json.gz'));
        $result = NpmLock::parse($contents, new Limits());

        self::assertSame('too_large', $result->status);
        self::assertSame([], $result->deps);

        $smallLock = '{"lockfileVersion":3,"packages":{"node_modules/arg":{"version":"4.1.3"}}}';
        $result = NpmLock::parse(str_pad($smallLock, 10 * 1024 * 1024), new Limits());
        self::assertSame('ok', $result->status);
        self::assertCount(1, $result->deps);
    }

    public function testRowLimitIncludesPreviouslyParsedFiles(): void
    {
        $contents = $this->fixture('lockfiles/package-lock.v3-alias.hand.json');
        $result = NpmLock::parse($contents, new Limits(199_999));

        self::assertSame('too_many', $result->status);
        self::assertSame([], $result->deps);
        self::assertSame(2, count(NpmLock::parse($contents, new Limits(199_998))->deps));
    }

    public function testDepthLimitRejectsWholeFile(): void
    {
        $result = NpmLock::parse($this->fixture('hostile/json-nested-100.json'), new Limits());

        self::assertSame('parse_error', $result->status);
        self::assertSame([], $result->deps);
    }

    public function testDenseLockfileIsRejectedUnderTheScanMemoryLimit(): void
    {
        $script = <<<'PHP'
            $loader = require $argv[1].'/vendor/autoload.php';
            $loader->addPsr4('Kanboard\\Plugin\\Gumshoe\\', $argv[1]);
            $contents = '{"lockfileVersion":3,"packages":{';
            for ($i = 0; $i < 180_000; ++$i) {
                $contents .= '"node_modules/dep-'.$i.'":{"version":"1"},';
            }
            $contents .= '"":{}}}';
            $result = \Kanboard\Plugin\Gumshoe\Inventory\NpmLock::parse(
                $contents,
                new \Kanboard\Plugin\Gumshoe\Inventory\Limits(),
            );
            echo $result->status, ':', count($result->deps);
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
        self::assertSame('too_many:0', $output);
    }

    public function testRegistryEvidenceRequiresTheExactPackageTarball(): void
    {
        $tarball = 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz';
        $result = NpmLock::parse(json_encode([
            'lockfileVersion' => 3,
            'packages' => [
                'node_modules/lodash' => ['version' => '4.17.21', 'resolved' => $tarball],
                'node_modules/clone/node_modules/lodash' => ['version' => '4.17.20', 'resolved' => $tarball],
                'node_modules/@acme/secret-payroll' => [
                    'version' => 'ghp_'.str_repeat('A1', 18),
                    'resolved' => $tarball,
                ],
                'node_modules/@actions/core' => [
                    'version' => '1.6.0',
                    'resolved' => 'https://registry.npmjs.org/@actions%2fcore/-/core-1.6.0.tgz',
                ],
                'node_modules/once' => [
                    'version' => '1.4.0',
                    'resolved' => 'https://registry.npmjs.org/once/-/once-1.4.0.tgz?query=1',
                ],
                'node_modules/wrappy' => [
                    'version' => '1.0.2',
                    'resolved' => 'http://registry.npmjs.org/wrappy/-/wrappy-1.0.2.tgz',
                ],
            ],
        ], JSON_THROW_ON_ERROR), new Limits());

        self::assertSame('ok', $result->status);
        self::assertSame(['npmjs', null, null, 'npmjs', null, null], array_column($result->deps, 'registry_evidence'));

        $fixture = NpmLock::parse($this->fixture('lockfiles/package-lock.v2.json'), new Limits());
        self::assertSame('ok', $fixture->status);
        self::assertSame('npmjs', array_column($fixture->deps, 'registry_evidence', 'name')['@actions/core']);
    }

    public function testPackageNameIsPreservedVerbatim(): void
    {
        $result = NpmLock::parse($this->fixture('hostile/package-lock-script-name.json'), new Limits());

        self::assertSame('ok', $result->status);
        self::assertSame(['</script><img src=x>'], array_column($result->deps, 'name'));
    }

    public function testUnsupportedVersionAndMalformedPackageMapAreIncomplete(): void
    {
        $result = NpmLock::parse('{"lockfileVersion":4,"packages":{}}', new Limits());
        self::assertSame('unsupported', $result->status);
        self::assertSame([], $result->deps);

        $result = NpmLock::parse('{"lockfileVersion":3,"packages":[null]}', new Limits());
        self::assertSame('parse_error', $result->status);
        self::assertSame([], $result->deps);

        $result = NpmLock::parse('{"lockfileVersion":3,"packages":[]}', new Limits());
        self::assertSame('parse_error', $result->status);
        self::assertSame([], $result->deps);

        $result = NpmLock::parse('{"lockfileVersion":1,"dependencies":{"0":{}}}', new Limits());
        self::assertSame('ok', $result->status);
        self::assertSame(['0'], array_column($result->deps, 'name'));
    }

    private function fixture(string $path): string
    {
        return file_get_contents(__DIR__.'/fixtures/'.$path);
    }
}
