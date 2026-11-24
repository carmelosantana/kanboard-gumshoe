<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use InvalidArgumentException;
use Kanboard\Plugin\Gumshoe\Advisory\GroupStore;
use KanboardTests\units\Base;
use PDO;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/ReleasesConnection.php';

final class GroupStoreTest extends Base
{
    use ReleasesConnection;

    private PDO $pdo;
    private GroupStore $store;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $this->pdo = $this->container['db']->getConnection();
        version_1($this->pdo);
        $this->store = new GroupStore($this->pdo);
    }

    public function testNewGroupPersistsAndEachNewAliasJoinsIt(): void
    {
        $first = $this->store->resolve(['PYSEC-2017-22']);
        $id = $first['group']['id'];
        self::assertGreaterThan(0, $id);
        self::assertSame('PYSEC-2017-22', $first['group']['primary_id']);
        self::assertSame([], $first['merged']);

        $store = new GroupStore($this->pdo);
        $aliases = ['PYSEC-2017-22', 'MAL-2025-20690', 'GHSA-ggv3-7p47-pfv8', 'CVE-2021-3129'];
        for ($i = 1; $i < count($aliases); $i++) {
            $resolved = $store->resolve([$aliases[$i - 1], $aliases[$i], $aliases[$i]]);
            self::assertSame($id, $resolved['group']['id']);
            self::assertSame($aliases[$i], $resolved['group']['primary_id']);
            self::assertSame([], $resolved['merged']);
        }

        // Looking up a lower-ranked alias must retain the existing primary id.
        self::assertSame($resolved, $store->resolve([$aliases[0]]));
        self::assertSame(1, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_groups')->fetchColumn());
        self::assertSame(4, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_group_aliases')->fetchColumn());
    }

    public function testMergeKeepsOldestGroupAndAllAliasesAndSeverityEvidence(): void
    {
        $older = $this->store->resolve(['PYSEC-2017-22', 'MAL-2025-20690'])['group']['id'];
        $newer = $this->store->resolve(['GHSA-ggv3-7p47-pfv8', 'CVE-2021-3129'])['group']['id'];
        $newest = $this->store->resolve(['CVE-2025-42884'])['group']['id'];
        $this->pdo->prepare('UPDATE gumshoe_groups SET cvss_max = ?, malware = ? WHERE id = ?')
            ->execute([6.9, 1, $older]);
        $this->pdo->prepare('UPDATE gumshoe_groups SET cvss_max = ?, kev = ? WHERE id = ?')
            ->execute([9.8, 1, $newer]);

        $result = $this->store->resolve([
            'CVE-2025-42884', 'GHSA-ggv3-7p47-pfv8', 'PYSEC-2017-22', 'GHSA-4qwp-7c67-jmcc',
        ]);
        self::assertSame([$newer, $newest], $result['merged']);
        self::assertSame([
            'id' => $older,
            'primary_id' => 'CVE-2021-3129',
            'cvss_max' => 9.8,
            'malware' => true,
            'kev' => true,
        ], $result['group']);

        $mergedInto = $this->pdo->query('SELECT merged_into FROM gumshoe_groups ORDER BY id')->fetchAll(PDO::FETCH_COLUMN);
        self::assertSame([null, $older, $older], array_map(
            static fn ($id) => $id === null ? null : (int) $id,
            $mergedInto,
        ));
        foreach ($this->pdo->query('SELECT group_id FROM gumshoe_group_aliases') as $row) {
            self::assertSame($older, (int) $row['group_id']);
        }
        self::assertSame(6, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_group_aliases')->fetchColumn());

        $store = new GroupStore($this->pdo);
        self::assertSame(
            ['group' => $result['group'], 'merged' => []],
            $store->resolve(['CVE-2021-3129', 'MAL-2025-20690', 'GHSA-4qwp-7c67-jmcc']),
        );
    }

    public function testEmptyAliasListIsRejected(): void
    {
        $this->expectException(InvalidArgumentException::class);
        $this->store->resolve([]);
    }
}
