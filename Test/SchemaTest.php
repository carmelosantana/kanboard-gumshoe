<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use KanboardTests\units\Base;
use PDO;
use PDOException;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;
use const Kanboard\Plugin\Gumshoe\Schema\VERSION;

require_once 'tests/units/Base.php';
require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/ReleasesConnection.php';

class SchemaTest extends Base
{
    use ReleasesConnection;

    public function testVersion1(): void
    {
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $pdo = $this->container['db']->getConnection();
        version_1($pdo);
        $this->assertSame(1, VERSION);

        $this->assertRow($pdo, 'settings', [
            'watch_id' => 1, 'window_days' => 90, 'forks' => 0, 'archived' => 0,
            'scanning' => 1, 'hourly' => 1, 'project_id' => null, 'deny_prefixes' => '', 'revision' => 0,
        ]);
        $this->assertRow($pdo, 'state', [
            'name' => 'writer', 'holder' => null, 'lease_until' => 0, 'run_id' => null,
        ]);
        $pdo->exec("UPDATE gumshoe_settings SET project_id = 7, deny_prefixes = '@example/', revision = 2");
        $this->assertRow($pdo, 'settings', ['project_id' => 7, 'deny_prefixes' => '@example/', 'revision' => 2]);

        $path = str_repeat('a/', 507).'Abcde.lock';
        $otherPath = strtolower($path);
        $run = [
            'id' => 1, 'job' => 'gumshoe.inventory', 'trigger' => 'cli', 'phase' => 'inventory',
            'position' => '{"repo_id":1}', 'status' => 'more', 'counts' => '{"complete":1}',
            'exception_class' => null, 'retry_at' => 1700000020, 'started_at' => 1700000000, 'finished_at' => null,
        ];
        $rows = [
            'owners' => [
                'id' => 1, 'watch_id' => 1, 'login' => 'symfony', 'kind' => 'org', 'enabled' => 1,
                'token_ref' => 'vault://1/token', 'token_status' => 'expiring', 'token_expires_at' => 1800000000,
            ],
            'repos' => [
                'id' => 1, 'owner_id' => 1, 'name' => 'yaml', 'github_id' => 4294967297,
                'mode' => 'pin', 'private' => 0, 'fork' => 0, 'archived' => 0, 'pushed_at' => 1700000000,
                'default_branch' => 'main', 'head_sha' => str_repeat('a', 40), 'tree_sha' => str_repeat('b', 40),
                'outcome' => 'complete', 'last_complete_at' => 1700000010, 'gone_at' => null,
            ],
            'lockfiles' => [
                'id' => 1, 'repo_id' => 1, 'path_hash' => hash('sha256', $path), 'path' => $path,
                'blob_sha' => str_repeat('c', 40), 'kind' => 'composer', 'status' => 'ok', 'parser_version' => 1,
                'last_complete_blob_sha' => str_repeat('c', 40),
            ],
            'deps' => [
                'lockfile_id' => 1, 'ecosystem' => 'Packagist', 'name' => 'symfony/yaml', 'version' => '7.4.23',
                'scope' => 'prod', 'source' => 'packagist', 'query_type' => 'package', 'egress' => 'public',
            ],
            'runs' => $run,
            'dep_changes' => [
                'run_id' => 1, 'repo_id' => 1, 'kind' => 'changed', 'ecosystem' => 'Packagist',
                'name' => 'symfony/yaml', 'from_version' => '7.4.22', 'to_version' => '7.4.23',
                'path' => $path, 'created_at' => 1700000010,
            ],
            'groups' => [
                'id' => 1, 'primary_id' => 'CVE-2000-0001', 'cvss_max' => 7.5,
                'malware' => 0, 'kev' => 0, 'merged_into' => null,
            ],
            'group_aliases' => ['alias' => 'CVE-2000-0001', 'group_id' => 1],
            'advisory_cache' => [
                'source' => 'osv', 'advisory_id' => 'CVE-2000-0001', 'modified' => '2026-11-23T00:00:00Z',
                'body' => '{}', 'fetched_at' => 1700000015,
            ],
            'findings' => [
                'id' => 1, 'group_id' => 1, 'ecosystem' => 'Packagist', 'package' => 'symfony/yaml',
                'task_id' => 8, 'project_id' => 7, 'priority' => 'high', 'status' => 'open',
                'closed_by_gumshoe_at' => null, 'last_synced_at' => 1700000016,
                'reopened_by_person_at' => 1700000017, 'observed_priority' => 'high',
                'observed_malware' => 1, 'observed_kev' => 0, 'observed_status' => 'open',
            ],
            'finding_repos' => [
                'finding_id' => 1, 'repo_id' => 1, 'subtask_id' => 9, 'state' => 'affected', 'ever_affected' => 1,
            ],
            'exposures' => [
                'finding_id' => 1, 'repo_id' => 1, 'lockfile_id' => 1, 'version' => '7.4.23',
                'active' => 1, 'first_seen' => 1700000015, 'last_seen' => 1700000016,
            ],
            'pending' => [
                'run_id' => 1, 'query_type' => 'package', 'ecosystem' => 'Packagist', 'name' => 'symfony/yaml',
                'version' => '7.4.23', 'egress' => 'public', 'state' => 'pending', 'page_token' => 'next-page',
                'retry_at' => 1700000020,
            ],
        ];
        foreach ($rows as $table => $row) {
            $this->insert($pdo, $table, $row);
            $this->assertRow($pdo, $table, $row);
        }
        $alternateLockfile = array_replace($rows['lockfiles'], [
            'id' => 2, 'path_hash' => hash('sha256', $otherPath), 'path' => $otherPath,
        ]);
        $this->insert($pdo, 'lockfiles', $alternateLockfile);
        $this->assertRow($pdo, 'lockfiles', $alternateLockfile, 'WHERE id = 2');
        $this->assertSame(1, (int) $pdo->query('SELECT COUNT(*) FROM gumshoe_lockfiles WHERE path = '.$pdo->quote($path))->fetchColumn());
        $pdo->exec("UPDATE gumshoe_state SET holder = 'slice-1', lease_until = 1700000060, run_id = 1 WHERE name = 'writer'");
        $this->assertRow($pdo, 'state', ['holder' => 'slice-1', 'lease_until' => 1700000060, 'run_id' => 1]);

        // Change other keys where applicable, so each insert tests only the named constraint.
        $this->assertRejectedInsert($pdo, 'settings', ['watch_id' => 1], 'watch primary key');
        $this->assertRejectedInsert($pdo, 'settings', ['watch_id' => 2], 'singleton watch');
        $this->assertRejectedInsert($pdo, 'state', ['name' => 'writer'], 'state primary key');
        $this->assertRejectedInsert($pdo, 'owners', ['id' => 2] + $rows['owners'], 'watch and login');
        $this->assertRejectedInsert($pdo, 'repos', ['id' => 2, 'name' => 'console'] + $rows['repos'], 'GitHub id');
        $this->assertRejectedInsert($pdo, 'repos', ['id' => 2, 'github_id' => 4294967298] + $rows['repos'], 'owner and name');
        $this->assertRejectedInsert($pdo, 'lockfiles', ['id' => 3] + $rows['lockfiles'], 'repo and path hash');
        $this->assertRejectedInsert($pdo, 'group_aliases', $rows['group_aliases'], 'alias');
        $this->assertRejectedInsert($pdo, 'advisory_cache', $rows['advisory_cache'], 'source and advisory id');
        $this->assertRejectedInsert($pdo, 'findings', ['id' => 2] + $rows['findings'], 'group, ecosystem and package');
        $this->assertRejectedInsert($pdo, 'finding_repos', $rows['finding_repos'], 'finding and repo');
        $this->assertRejectedInsert($pdo, 'exposures', $rows['exposures'], 'finding, repo, lockfile and version');
        $this->assertRejectedInsert($pdo, 'pending', $rows['pending'], 'run and query tuple');

        $this->assertRejectedInsert($pdo, 'repos', [
            'id' => 2, 'owner_id' => 999, 'name' => 'console', 'github_id' => 4294967298,
        ] + $rows['repos'], 'repo owner foreign key');
        $this->assertRejectedInsert($pdo, 'deps', ['lockfile_id' => 999] + $rows['deps'], 'dependency lockfile foreign key');
        $this->assertRejectedInsert($pdo, 'group_aliases', [
            'alias' => 'CVE-2000-0002', 'group_id' => 999,
        ], 'alias group foreign key');

        $pdo->exec('DELETE FROM gumshoe_lockfiles WHERE id = 1');
        $this->assertSame(0, (int) $pdo->query('SELECT COUNT(*) FROM gumshoe_deps')->fetchColumn());
        $pdo->exec('DELETE FROM gumshoe_owners WHERE id = 1');
        $this->assertSame(0, (int) $pdo->query('SELECT COUNT(*) FROM gumshoe_repos')->fetchColumn());
    }

    private function insert(PDO $pdo, string $table, array $row): void
    {
        $quote = DB_DRIVER === 'mysql' ? chr(96) : '"';
        $columns = array_map(static fn ($column) => $quote.$column.$quote, array_keys($row));
        $parameters = implode(', ', array_fill(0, count($row), '?'));
        $pdo->prepare("INSERT INTO gumshoe_$table (".implode(', ', $columns).") VALUES ($parameters)")
            ->execute(array_values($row));
    }

    private function assertRow(PDO $pdo, string $table, array $expected, string $where = ''): void
    {
        $row = $pdo->query("SELECT * FROM gumshoe_$table $where")->fetch(PDO::FETCH_ASSOC);
        $this->assertIsArray($row, $table);
        foreach ($expected as $column => $value) {
            $this->assertArrayHasKey($column, $row, $table);
            $actual = $row[$column];
            if (is_numeric($actual) && (is_int($value) || is_float($value))) {
                $actual += 0;
            }
            $this->assertSame($value, $actual, "$table.$column");
        }
    }

    private function assertRejectedInsert(PDO $pdo, string $table, array $row, string $constraint): void
    {
        try {
            $this->insert($pdo, $table, $row);
        } catch (PDOException $exception) {
            // MySQL reports a CHECK violation as HY000 with driver error 3819.
            $this->assertTrue(
                str_starts_with((string) $exception->getCode(), '23')
                || ($constraint === 'singleton watch' && ($exception->errorInfo[1] ?? null) === 3819),
                $constraint
            );
            return;
        }

        $this->fail("Insert succeeded despite the $constraint constraint.");
    }
}
