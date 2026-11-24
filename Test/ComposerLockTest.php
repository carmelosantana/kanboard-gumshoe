<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Inventory\ComposerLock;
use Kanboard\Plugin\Gumshoe\Inventory\Limits;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class ComposerLockTest extends TestCase
{
    public function testParsesProductionAndDevelopmentPackages(): void
    {
        $result = ComposerLock::parse(file_get_contents(__DIR__.'/fixtures/lockfiles/composer.lock'), new Limits());
        self::assertSame('ok', $result->status);

        $byName = array_column($result->deps, null, 'name');
        $package = $byName['composer/ca-bundle'];
        self::assertSame('composer', $package->ecosystem);
        self::assertSame('prod', $package->scope);
        self::assertSame('1.6.1', $package->version);
        self::assertSame('packagist', $package->registry_evidence);
        self::assertSame('package', $package->query_type);
        self::assertSame('0c64479fae6952ba4cf021a72c0ac530394c91d4', $package->source);
        self::assertSame('dev', $byName['phpstan/phpstan']->scope);
    }

    public function testStripsOnlyOneLeadingVAndRequiresPackagistEvidence(): void
    {
        $result = ComposerLock::parse(<<<'JSON'
            {"packages":[
                {"name":"psr/log","version":"v3.0.2"},
                {"name":"psr/container","version":"vv2.0.2","notification-url":"https://packagist.org.example/downloads/"}
            ],"packages-dev":[]}
            JSON, new Limits());

        self::assertSame('ok', $result->status);
        self::assertSame(['3.0.2', 'v2.0.2'], array_column($result->deps, 'version'));
        self::assertSame([null, null], array_column($result->deps, 'registry_evidence'));
    }

    public function testMalformedPackageRejectsWholeFile(): void
    {
        $result = ComposerLock::parse('{"packages":[{"name":"psr/log","version":"3.0.2"},null]}', new Limits());

        self::assertSame('parse_error', $result->status);
        self::assertSame([], $result->deps);
    }

    public function testRowLimitIncludesProductionAndDevelopment(): void
    {
        $contents = <<<'JSON'
            {"packages":[{"name":"psr/log","version":"3.0.2"}],
             "packages-dev":[{"name":"phpstan/phpstan","version":"2.1.0"}]}
            JSON;

        self::assertSame('ok', ComposerLock::parse($contents, new Limits(199_998))->status);
        $result = ComposerLock::parse($contents, new Limits(199_999));
        self::assertSame('too_many', $result->status);
        self::assertSame([], $result->deps);
    }
}
