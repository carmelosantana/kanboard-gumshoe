<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Inventory\Dependency;
use Kanboard\Plugin\Gumshoe\Inventory\Limits;
use Kanboard\Plugin\Gumshoe\Inventory\PnpmLock;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class PnpmLockTest extends TestCase
{
    public function testWorkspaceVersionsGiveTheSameRowsForTheSameTree(): void
    {
        $v6 = $this->fixture('pnpm-lock.v6-workspace.yaml');
        $v9 = <<<'YAML'
            lockfileVersion: '9.0'
            importers:
              .:
                dependencies:
                  is-positive: {specifier: 1.0.0, version: 1.0.0}
              packages/f:
                dependencies:
                  is-negative: {specifier: 1.0.0, version: 1.0.0}
              packages/g:
                dependencies:
                  '@pnpm.e2e/external-depend-on-internal-dep': {specifier: 1.0.0, version: 1.0.0}
            packages:
              '@pnpm.e2e/external-depend-on-internal-dep@1.0.0': {}
              is-negative@1.0.0: {}
              is-positive@1.0.0: {}
            snapshots:
              '@pnpm.e2e/external-depend-on-internal-dep@1.0.0': {}
              is-negative@1.0.0: {}
              is-positive@1.0.0: {}
            YAML;
        $expected = array_map(
            static fn ($name) => new Dependency('npm', $name, '1.0.0', 'prod', null, 'package', 'npmjs'),
            ['@pnpm.e2e/external-depend-on-internal-dep', 'is-negative', 'is-positive'],
        );

        foreach ([$v6, str_replace('/is-negative@1.0.0:', '/is-negative/1.0.0:', $v6), $v9] as $contents) {
            $result = PnpmLock::parse($contents, new Limits());
            self::assertSame('ok', $result->status);
            self::assertEquals($expected, $result->deps);
        }
    }

    public function testPeerSuffixesAreStrippedAndWorkspaceDevScopeIsPreserved(): void
    {
        $v6 = PnpmLock::parse($this->fixture('pnpm-lock.v6-peers.yaml'), new Limits());
        self::assertSame('ok', $v6->status);
        self::assertContains('@pnpm.e2e/abc', array_column($v6->deps, 'name'));
        $abc = array_column($v6->deps, null, 'name')['@pnpm.e2e/abc'];
        self::assertSame('1.0.0', $abc->version);

        $v9 = PnpmLock::parse(<<<'YAML'
            lockfileVersion: '9.0'
            importers:
              packages/dev:
                devDependencies:
                  is-odd: {version: 3.0.1(is-number@6.0.0)}
            packages:
              is-odd@3.0.1: {}
              is-number@6.0.0: {}
            snapshots:
              is-odd@3.0.1(is-number@6.0.0):
                dependencies:
                  is-number: 6.0.0
              is-odd@3.0.1(is-number@7.0.0): {}
              is-number@6.0.0: {}
            YAML, new Limits());

        self::assertSame('ok', $v9->status);
        self::assertSame(['is-odd', 'is-number'], array_column($v9->deps, 'name'));
        self::assertSame(['3.0.1', '6.0.0'], array_column($v9->deps, 'version'));
        self::assertSame(['dev', 'dev'], array_column($v9->deps, 'scope'));
    }

    public function testReadsBothDocumentsAndAppliesTheRowBudgetAcrossThem(): void
    {
        $contents = $this->fixture('pnpm-lock.v9-multidoc.hand.yaml');
        $result = PnpmLock::parse($contents, new Limits());
        self::assertSame('ok', $result->status);
        self::assertContains('@pnpm/exe.win32-x64', array_column($result->deps, 'name'));
        self::assertContains('is-number', array_column($result->deps, 'name'));

        $result = PnpmLock::parse($contents, new Limits(Limits::MAX_REPO_DEPS - count($result->deps) + 1));
        self::assertSame('too_many', $result->status);
        self::assertSame([], $result->deps);
    }

    public function testUnsupportedDocumentDiscardsAllRows(): void
    {
        $result = PnpmLock::parse($this->fixture('pnpm-lock.v9-v13-multidoc.yaml'), new Limits());

        self::assertSame('unsupported', $result->status);
        self::assertSame([], $result->deps);
    }

    public function testRegistryEvidenceComesFromTarballOrDefaultRegistry(): void
    {
        $contents = <<<'YAML'
            lockfileVersion: '9.0'
            packages:
              is-positive@3.1.0: {resolution: {integrity: sha512-example}}
              is-odd@3.0.1: {resolution: {tarball: 'https://registry.npmjs.org.example/is-odd.tgz'}}
              is-number@6.0.0: {resolution: {tarball: 'https://registry.npmjs.org/is-number/-/is-number-6.0.0.tgz'}}
            YAML;

        $result = PnpmLock::parse($contents, new Limits());
        self::assertSame('ok', $result->status);
        self::assertSame(['npmjs', null, 'npmjs'], array_column($result->deps, 'registry_evidence'));

        foreach (["registry: https://example.com/\n", "settings: {registry: 'https://example.com/'}\n"] as $registry) {
            $result = PnpmLock::parse($registry.$contents, new Limits());
            self::assertSame('ok', $result->status);
            self::assertSame([null, null, 'npmjs'], array_column($result->deps, 'registry_evidence'));
        }
    }

    private function fixture(string $file): string
    {
        return file_get_contents(__DIR__.'/fixtures/lockfiles/'.$file);
    }
}
