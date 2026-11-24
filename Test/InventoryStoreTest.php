<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Inventory\Dependency;
use Kanboard\Plugin\Gumshoe\Inventory\ParseResult;
use Kanboard\Plugin\Gumshoe\Model\InventoryStore;
use KanboardTests\units\Base;
use PDO;
use RuntimeException;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/ReleasesConnection.php';

final class InventoryStoreTest extends Base
{
    use ReleasesConnection;

    private const PATH = 'package-lock.json';
    private const OTHER_PATH = 'tools/package-lock.json';

    private PDO $pdo;
    private InventoryStore $store;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $this->pdo = $this->container['db']->getConnection();
        version_1($this->pdo);
        $this->pdo->exec("INSERT INTO gumshoe_owners (login, kind) VALUES ('octokit', 'org')");
        $this->pdo->exec("INSERT INTO gumshoe_repos (owner_id, name, github_id) VALUES (1, 'rest.js', 1)");
        $this->store = new InventoryStore($this->pdo);
    }

    public function testFirstCompleteScanRecordsBaselineThenVersionChanges(): void
    {
        $this->apply(1, [$this->file('a', $this->parsed('4.0.0'))]);
        self::assertSame(['new_repo'], array_column($this->rows('dep_changes'), 'kind'));
        self::assertSame([
            'ecosystem' => 'npm', 'name' => 'universal-user-agent', 'version' => '4.0.0',
            'scope' => 'prod', 'source' => null, 'query_type' => 'package', 'egress' => 'unqueryable',
        ], array_diff_key($this->rows('deps')[0], array_flip(['id', 'lockfile_id'])));
        $firstFileId = $this->rows('lockfiles')[0]['id'];

        $this->apply(2, [$this->file('b', $this->parsed('4.0.1'))]);
        self::assertSame(['4.0.1'], array_column($this->rows('deps'), 'version'));
        self::assertSame($firstFileId, $this->rows('lockfiles')[0]['id']);
        $change = $this->rows('dep_changes')[1];
        self::assertSame('changed', $change['kind']);
        self::assertSame(2, (int) $change['run_id']);
        self::assertSame(1, (int) $change['repo_id']);
        self::assertSame(self::PATH, $change['path']);
        self::assertSame('4.0.0', $change['from_version']);
        self::assertSame('4.0.1', $change['to_version']);
        self::assertSame('complete', $this->rows('repos')[0]['outcome']);
        self::assertSame($this->sha('2'), $this->rows('repos')[0]['head_sha']);
        self::assertSame($this->sha('f'), $this->rows('repos')[0]['tree_sha']);
    }

    public function testReusesSuccessfulParseUntilParserVersionChanges(): void
    {
        $calls = 0;
        $parse = function () use (&$calls): ParseResult {
            ++$calls;
            return $this->parsed('4.0.0');
        };

        $this->apply(1, [$this->file('a', $parse)]);
        self::assertSame(1, $calls);
        $before = $this->rows('deps');
        $this->apply(2, [$this->file('a', $parse)]);
        self::assertSame(1, $calls);
        self::assertSame($before, $this->rows('deps'));
        $this->apply(3, [$this->file('a', $parse, parserVersion: 2)]);
        self::assertSame(2, $calls);
        self::assertSame(2, (int) $this->rows('lockfiles')[0]['parser_version']);
        self::assertSame(['new_repo'], array_column($this->rows('dep_changes'), 'kind'));
    }

    public function testIncompleteParseKeepsLastCompleteRowsAndIsRetried(): void
    {
        $this->apply(1, [$this->file('a', $this->parsed('4.0.0'))]);
        $this->pdo->exec('UPDATE gumshoe_repos SET last_complete_at = 1700000000 WHERE id = 1');
        $deps = $this->rows('deps');

        $this->apply(2, [$this->file('b', new ParseResult($this->parsed('4.0.1')->deps, 'parse_error'))]);
        self::assertSame($deps, $this->rows('deps'));
        $file = $this->rows('lockfiles')[0];
        self::assertSame('stale', $file['status']);
        self::assertSame($this->sha('b'), $file['blob_sha']);
        self::assertSame($this->sha('a'), $file['last_complete_blob_sha']);
        self::assertSame('partial', $this->rows('repos')[0]['outcome']);
        self::assertSame(1700000000, (int) $this->rows('repos')[0]['last_complete_at']);
        self::assertSame(['new_repo'], array_column($this->rows('dep_changes'), 'kind'));

        $this->apply(3, [$this->file('b', $this->parsed('4.0.1'))]);
        self::assertSame('ok', $this->rows('lockfiles')[0]['status']);
        self::assertSame($this->sha('b'), $this->rows('lockfiles')[0]['last_complete_blob_sha']);
        self::assertSame(['4.0.1'], array_column($this->rows('deps'), 'version'));
        self::assertSame('complete', $this->rows('repos')[0]['outcome']);
        self::assertGreaterThan(1700000000, (int) $this->rows('repos')[0]['last_complete_at']);
    }

    public function testOnlyCompleteTreeCanRemoveMissingLockfile(): void
    {
        $this->apply(1, [
            $this->file('a', $this->parsed('4.0.0')),
            $this->file('b', $this->parsed('3.0.0'), path: self::OTHER_PATH),
        ]);
        $before = $this->rows('lockfiles');
        $this->apply(2, [$this->file('a', $this->parsed('4.0.0'))], treeComplete: false);
        self::assertSame($before, $this->rows('lockfiles'));
        self::assertSame(['4.0.0', '3.0.0'], array_column($this->rows('deps'), 'version'));
        self::assertSame(['new_repo'], array_column($this->rows('dep_changes'), 'kind'));
        self::assertSame('partial', $this->rows('repos')[0]['outcome']);

        $this->apply(3, [$this->file('a', $this->parsed('4.0.0'))]);
        self::assertSame([self::PATH], array_column($this->rows('lockfiles'), 'path'));
        self::assertSame(['4.0.0'], array_column($this->rows('deps'), 'version'));
        self::assertSame(['new_repo', 'lockfile_gone'], array_column($this->rows('dep_changes'), 'kind'));
        self::assertSame(self::OTHER_PATH, $this->rows('dep_changes')[1]['path']);
    }

    public function testPartialFirstScanDoesNotEstablishBaseline(): void
    {
        $this->apply(1, [$this->file('a', new ParseResult([], 'unsupported'))]);
        self::assertSame('partial', $this->rows('repos')[0]['outcome']);
        self::assertNull($this->rows('repos')[0]['last_complete_at']);
        self::assertSame([], $this->rows('dep_changes'));

        $files = [
            $this->file('a', $this->parsed('4.0.0')),
            $this->file('b', $this->parsed('3.0.0'), path: self::OTHER_PATH),
        ];
        $this->apply(2, $files);
        $this->apply(3, $files);
        self::assertSame(['new_repo'], array_column($this->rows('dep_changes'), 'kind'));
        self::assertSame(2, (int) $this->rows('dep_changes')[0]['run_id']);
    }

    public function testThrowingParserRollsBackEarlierWritesForTheRepo(): void
    {
        $this->apply(1, [$this->file('a', $this->parsed('4.0.0'))]);
        $tables = ['repos', 'lockfiles', 'deps', 'dep_changes'];
        $before = array_map($this->rows(...), $tables);
        $error = new RuntimeException('Parser failure');

        try {
            $this->apply(2, [
                $this->file('b', $this->parsed('4.0.1')),
                $this->file('c', static function () use ($error): never {
                    throw $error;
                }, path: self::OTHER_PATH),
            ]);
            self::fail('The parser exception did not propagate.');
        } catch (RuntimeException $actual) {
            self::assertSame($error, $actual);
        }

        self::assertFalse($this->pdo->inTransaction());
        self::assertSame($before, array_map($this->rows(...), $tables));
        $this->apply(2, [$this->file('b', $this->parsed('4.0.1'))]);
        self::assertSame(['new_repo', 'changed'], array_column($this->rows('dep_changes'), 'kind'));
    }

    private function apply(int $runId, array $files, bool $treeComplete = true): void
    {
        $this->store->apply($runId, 1, [
            'treeComplete' => $treeComplete, 'headSha' => $this->sha((string) $runId), 'treeSha' => $this->sha('f'),
            'files' => $files,
        ]);
    }

    private function file(string $sha, ParseResult|callable $result, int $parserVersion = 1, string $path = self::PATH): array
    {
        return ['path' => $path, 'blob_sha' => $this->sha($sha), 'kind' => 'npm', 'parser_version' => $parserVersion, 'result' => $result];
    }

    private function sha(string $digit): string
    {
        return str_repeat($digit, 40);
    }

    private function parsed(string $version): ParseResult
    {
        return new ParseResult([new Dependency('npm', 'universal-user-agent', $version, 'prod', null, 'package', 'npmjs')]);
    }

    private function rows(string $table): array
    {
        return $this->pdo->query("SELECT * FROM gumshoe_$table ORDER BY id")->fetchAll(PDO::FETCH_ASSOC);
    }
}
