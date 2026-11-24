<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Egress\Policy;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Inventory\Dependency;
use Kanboard\Plugin\Gumshoe\Inventory\Limits;
use Kanboard\Plugin\Gumshoe\Inventory\NpmLock;
use Kanboard\Plugin\Gumshoe\Inventory\PnpmLock;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class EgressPolicyTest extends TestCase
{
    private const SHA = '11bd71901bbe5b1630ceea73d27597364c9af683';

    /** @dataProvider packageCases */
    public function testPackageVerdict(
        string $expected,
        string $ecosystem,
        string $name,
        ?string $evidence,
        ?string $version = '1.0.0',
        string $queryType = 'package',
        array $denyPrefixes = [],
    ): void {
        $dep = new Dependency($ecosystem, $name, $version, 'prod', null, $queryType, $evidence);
        self::assertSame($expected, (new Policy($denyPrefixes))->verdict($dep));
    }

    public static function packageCases(): iterable
    {
        yield 'npm scope and maximum version' => ['public', 'npm', '@types/node', 'npmjs', str_repeat('1', 128)];
        yield 'npm maximum name' => ['public', 'npm', str_repeat('a', 214), 'npmjs'];
        yield 'composer allows double hyphen in package' => ['public', 'composer', 'symfony/yaml--example', 'packagist'];
        yield 'missing npm evidence' => ['private', 'npm', 'lodash', null];
        yield 'missing composer evidence' => ['private', 'composer', 'symfony/yaml', null];
        yield 'unrecognized evidence' => ['private', 'npm', 'lodash', 'example.org'];
        yield 'registry must match ecosystem' => ['private', 'npm', 'lodash', 'packagist'];
        yield 'deny prefix' => ['denied', 'npm', '@types/node', 'npmjs', '1.0.0', 'package', ['@actions/', '@types/']];
        yield 'prefix only matches at start' => ['public', 'npm', '@types/node', 'npmjs', '1.0.0', 'package', ['node']];
        yield 'npm uppercase' => ['unqueryable', 'npm', 'Lodash', 'npmjs'];
        yield 'npm trailing newline' => ['unqueryable', 'npm', "lodash\n", 'npmjs'];
        yield 'npm name too long' => ['unqueryable', 'npm', str_repeat('a', 215), 'npmjs'];
        yield 'composer requires vendor' => ['unqueryable', 'composer', 'yaml', 'packagist'];
        yield 'composer vendor grammar' => ['unqueryable', 'composer', 'sym--fony/yaml', 'packagist'];
        yield 'composer package grammar' => ['unqueryable', 'composer', 'symfony/ya---ml', 'packagist'];
        yield 'version too long' => ['unqueryable', 'npm', 'lodash', 'npmjs', str_repeat('1', 129)];
        yield 'whitespace' => ['unqueryable', 'npm', 'lodash', 'npmjs', '1. 0'];
        yield 'control character' => ['unqueryable', 'npm', 'lodash', 'npmjs', "1.0\x7f"];
        yield 'missing version' => ['unqueryable', 'npm', 'lodash', 'npmjs', null];
        yield 'empty version' => ['unqueryable', 'npm', 'lodash', 'npmjs', ''];
        yield 'no query' => ['unqueryable', 'npm', 'lodash', 'npmjs', '1.0.0', 'none'];
        yield 'wrong query for package' => ['unqueryable', 'npm', 'lodash', 'npmjs', self::SHA, 'commit'];
        yield 'unsupported ecosystem' => ['unqueryable', 'docker', 'node', 'npmjs'];
    }

    /** @dataProvider actionCases */
    public function testActionVerdict(string $expected, array $visibility, string $name, string $version, string $queryType = 'commit', array $denyPrefixes = []): void
    {
        $dep = new Dependency('actions', $name, $version, 'action', null, $queryType, null);
        self::assertSame($expected, (new Policy($denyPrefixes, $visibility))->verdict($dep));
    }

    public static function actionCases(): iterable
    {
        yield 'canonical public repository' => ['public', ['actions/checkout' => true], 'Actions/Checkout', self::SHA];
        yield 'missing evidence in this run' => ['private', [], 'actions/checkout', self::SHA];
        yield 'explicitly nonpublic' => ['private', ['actions/checkout' => false], 'actions/checkout', self::SHA];
        yield 'unknown visibility' => ['private', ['actions/checkout' => null], 'actions/checkout', self::SHA];
        yield 'unrelated public repo' => ['private', ['actions/setup-node' => true], 'actions/checkout', self::SHA];
        yield 'mutable ref' => ['unqueryable', ['actions/checkout' => true], 'actions/checkout', 'v4', 'none'];
        yield 'invalid commit SHA' => ['unqueryable', ['actions/checkout' => true], 'actions/checkout', str_repeat('z', 40)];
        yield 'invalid repository name' => ['unqueryable', ['actions/..' => true], 'actions/..', self::SHA];
        yield 'action deny prefix' => ['denied', ['actions/checkout' => true], 'actions/checkout', self::SHA, 'commit', ['actions/']];
    }

    /** @dataProvider pnpmCases */
    public function testTarballLessPnpmEvidenceUsesRecordedConfig(string $expected, array|string $config): void
    {
        $result = PnpmLock::parse(<<<'YAML'
            lockfileVersion: '9.0'
            packages:
              '@types/node@22.0.0': {resolution: {}}
            YAML, new Limits());
        self::assertSame('ok', $result->status);
        self::assertSame('npmjs', $result->deps[0]->registry_evidence);
        self::assertSame($expected, (new Policy())->verdict($result->deps[0], 'pnpm', $config));
    }

    public static function pnpmCases(): iterable
    {
        yield 'configuration unknown' => ['private', 'unknown'];
        yield 'custom default registry' => ['private', ['registry' => 'example.org']];
        yield 'scope override' => ['private', ['@types' => 'example.org']];
        yield 'scope override on the npmjs host' => ['private', ['@types' => 'registry.npmjs.org']];
        yield 'known absent configuration' => ['public', []];
        yield 'npmjs default and unrelated scope' => ['public', ['registry' => 'registry.npmjs.org', '@actions' => 'example.org']];
    }

    public function testExplicitNpmjsTarballDoesNotDependOnRegistryConfig(): void
    {
        $result = PnpmLock::parse(<<<'YAML'
            lockfileVersion: '9.0'
            packages:
              lodash@4.17.21: {resolution: {tarball: 'https://registry.npmjs.org/lodash/-/lodash-4.17.21.tgz'}}
              arg@5.0.2: {resolution: {tarball: 'https://example.org/arg/-/arg-5.0.2.tgz'}}
            YAML, new Limits());
        self::assertSame('ok', $result->status);
        $policy = new Policy();
        self::assertSame('public', $policy->verdict($result->deps[0], 'pnpm'));
        self::assertSame('public', $policy->verdict($result->deps[0], 'pnpm', ['registry' => 'example.org']));
        self::assertSame('private', $policy->verdict($result->deps[1], 'pnpm', []));
    }

    public function testInferredNpmEvidenceRequiresPnpmRegistryConfig(): void
    {
        $dep = new Dependency('npm', 'lodash', '1.0.0', 'prod', null, 'package', 'npmjs', evidence_inferred: true);
        $policy = new Policy();
        self::assertSame('private', $policy->verdict($dep));
        self::assertSame('private', $policy->verdict($dep, 'npm', []));
    }

    public function testClassificationDoesNotSendHttpRequests(): void
    {
        $transport = new FakeTransport([new Response(200, [], file_get_contents(__DIR__.'/fixtures/github/repo.json'))]);
        $client = new Client($transport, 'http://localhost');
        $response = $client->send(new Request('gh.repo', 'https://api.github.com/repos/carmelosantana/ai-context-builder'));
        $repo = json_decode($response->body, flags: JSON_THROW_ON_ERROR);
        $policy = new Policy(githubVisibility: [$repo->full_name => $repo->private === false]);
        $requests = $transport->requests;

        $recorded = new Dependency('actions', $repo->full_name, self::SHA, 'action', null, 'commit', null);
        $unknown = new Dependency('actions', 'actions/checkout', self::SHA, 'action', null, 'commit', null);
        self::assertSame('public', $policy->verdict($recorded));
        self::assertSame('private', $policy->verdict($unknown));
        self::assertSame($requests, $transport->requests);
    }

    public function testHostileNpmNameIsUnqueryableDespiteRegistryEvidence(): void
    {
        $result = NpmLock::parse(file_get_contents(__DIR__.'/fixtures/hostile/package-lock-script-name.json'), new Limits());
        self::assertSame('ok', $result->status);
        $dep = $result->deps[0];
        self::assertSame('</script><img src=x>', $dep->name);
        self::assertSame('npmjs', $dep->registry_evidence);
        self::assertSame('unqueryable', (new Policy())->verdict($dep, 'npm'));
    }

    public function testWorkspaceDependenciesArePrivateAndExcludedFromCoverageGaps(): void
    {
        $result = NpmLock::parse(file_get_contents(__DIR__.'/fixtures/lockfiles/package-lock.v3-workspace.json'), new Limits());
        $policy = new Policy();
        $workspace = $result->deps[1];
        $unverified = new Dependency('npm', 'lodash', '1.0.0', 'prod', null, 'package', null);

        self::assertSame('workspace', $workspace->source);
        self::assertSame('private', $policy->verdict($workspace));
        self::assertFalse($policy->isCoverageGap($workspace, 'private'));
        self::assertTrue($policy->isCoverageGap($unverified, 'private'));
        self::assertFalse($policy->isCoverageGap($result->deps[0], 'public'));

        $withEvidence = new Dependency('npm', 'lodash', '1.0.0', 'prod', 'workspace', 'package', 'npmjs');
        self::assertSame('private', $policy->verdict($withEvidence, 'npm'));
    }
}
