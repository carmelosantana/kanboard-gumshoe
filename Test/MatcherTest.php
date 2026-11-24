<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Advisory\GroupStore;
use Kanboard\Plugin\Gumshoe\Finding\Matcher;
use KanboardTests\units\Base;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once __DIR__.'/bootstrap.php';
require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';

final class MatcherTest extends Base
{
    use ReleasesConnection;

    private const MAL = 'MAL-2025-20690';
    private const GHSA = 'GHSA-9gx6-6372-9mwg';
    private const SHA = '11bd71901bbe5b1630ceea73d27597364c9af683';
    private const OTHER_SHA = '692973e3d937129bcbf40652eb9f2f61becf3332';

    private GroupStore $groups;

    protected function setUp(): void
    {
        parent::setUp();
        $pdo = $this->container['db']->getConnection();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        version_1($pdo);
        $this->groups = new GroupStore($pdo);
    }

    public function testResolvesAliasesBeforeDeduplicatingExposuresAndKeepsDistinctLockfiles(): void
    {
        $older = $this->groups->resolve([self::GHSA])['group']['id'];
        $newer = $this->groups->resolve([self::MAL])['group']['id'];
        $first = self::dependency(1, 17, 23);
        $second = self::dependency(2, 17, 24);
        $third = self::dependency(3, 18, 25, version: '0.1.2');
        $githubOnly = self::dependency(4, 17, 23, version: '0.1.0');

        $result = (new Matcher($this->groups))->exposures(
            [$first, $second, $third, $githubOnly],
            [self::pending(71, $first), self::pending(72, $third)],
            [71 => [['id' => self::MAL]], 72 => [['id' => self::MAL, 'aliases' => [self::GHSA]]]],
            array_fill_keys([1, 4], [['ghsa_id' => self::GHSA, 'cve_id' => null]]),
        );

        self::assertSame([
            self::exposure($older, $first),
            self::exposure($older, $second),
            self::exposure($older, $third),
            self::exposure($older, $githubOnly),
        ], $result['exposures']);
        self::assertSame([$newer => $older], $result['merged']);
        self::assertSame([], $result['coverage_gaps']);
    }

    public function testNonPublicDependenciesNeverMatchAndGapsAreCountedPerRepo(): void
    {
        $public = self::dependency(1, 17, 23);
        $denied = self::dependency(2, 17, 24, egress: 'denied');
        $private = self::dependency(3, 17, 25, egress: 'private');
        $unqueryable = self::dependency(4, 18, 26, egress: 'unqueryable');
        $workspace = self::dependency(5, 18, 27, egress: 'private') + ['source' => 'workspace'];

        $result = (new Matcher($this->groups))->exposures(
            [$public, $denied, $private, $unqueryable, $workspace],
            [self::pending(71, $public)],
            [71 => [['id' => self::MAL]]],
            array_fill_keys([2, 3, 4, 5], [['ghsa_id' => self::GHSA]]),
        );

        $group = $this->groups->resolve([self::MAL])['group']['id'];
        self::assertSame([self::exposure($group, $public)], $result['exposures']);
        self::assertSame([17 => 2, 18 => 1], $result['coverage_gaps']);
    }

    public function testActionsMatchOnlyTheResultForTheirOwnCommitQuery(): void
    {
        $affected = self::dependency(1, 17, 23, 'actions', 'actions/checkout', self::SHA, 'commit');
        $clean = self::dependency(2, 17, 24, 'actions', 'actions/checkout', self::OTHER_SHA, 'commit');
        $differentQueryType = array_replace($clean, ['query_type' => 'package']);

        $result = (new Matcher($this->groups))->exposures(
            [$affected, $clean],
            [self::pending(74, $clean), self::pending(71, $affected), self::pending(80, $differentQueryType)],
            [80 => [['id' => self::MAL]], 71 => [['id' => 'GHSA-mrrh-fwg8-r2c3']], 74 => []],
            [2 => [['ghsa_id' => self::GHSA]]],
        );

        $group = $this->groups->resolve(['GHSA-mrrh-fwg8-r2c3'])['group']['id'];
        self::assertSame([self::exposure($group, $affected)], $result['exposures']);
        self::assertSame([], $result['coverage_gaps']);
    }

    private static function dependency(
        int $id,
        int $repo,
        int $lockfile,
        string $ecosystem = 'npm',
        string $name = 'flatmap-stream',
        string $version = '0.1.1',
        string $type = 'package',
        string $egress = 'public',
    ): array {
        return [
            'id' => $id,
            'repo_id' => $repo,
            'lockfile_id' => $lockfile,
            'ecosystem' => $ecosystem,
            'name' => $name,
            'version' => $version,
            'query_type' => $type,
            'egress' => $egress,
        ];
    }

    private static function pending(int $id, array $dep): array
    {
        return ['id' => $id] + array_intersect_key($dep, array_flip(['ecosystem', 'name', 'version', 'query_type', 'egress']));
    }

    private static function exposure(int $group, array $dep): array
    {
        return [
            'group_id' => $group,
            'ecosystem' => $dep['ecosystem'],
            'package' => $dep['name'],
            'repo_id' => $dep['repo_id'],
            'lockfile_id' => $dep['lockfile_id'],
            'version' => $dep['version'],
        ];
    }
}
