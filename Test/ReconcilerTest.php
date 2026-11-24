<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Egress\Policy;
use Kanboard\Plugin\Gumshoe\Finding\Reconciler;
use Kanboard\Plugin\Gumshoe\GitHub\TreeReader;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Inventory\ParseResult;
use Kanboard\Plugin\Gumshoe\Model\FindingModel;
use Kanboard\Plugin\Gumshoe\Model\InventoryStore;
use Kanboard\Plugin\Gumshoe\Secrets\VaultTokenSource;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeVaultSecrets;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use PDO;
use KanboardTests\units\Base;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once __DIR__.'/bootstrap.php';
require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';
require_once __DIR__.'/Fakes/FakeVaultSecrets.php';

final class ReconcilerTest extends Base
{
    use ReleasesConnection;

    private PDO $pdo;

    protected function setUp(): void
    {
        parent::setUp();
        $this->pdo = $this->container['db']->getConnection();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        version_1($this->pdo);
        $this->pdo->exec(<<<'SQL'
            INSERT INTO gumshoe_owners (login, kind) VALUES ('octokit', 'org');
            INSERT INTO gumshoe_repos (owner_id, name, github_id, outcome)
                VALUES (1, 'rest.js', 1, 'complete'), (1, 'core.js', 2, 'complete');
            INSERT INTO gumshoe_groups (primary_id) VALUES ('GHSA-9gx6-6372-9mwg');
            INSERT INTO gumshoe_findings (group_id, ecosystem, package) VALUES (1, 'npm', 'flatmap-stream');
            INSERT INTO gumshoe_finding_repos (finding_id, repo_id, subtask_id, state, ever_affected)
                VALUES (1, 1, 7, 'affected', 1);
            INSERT INTO gumshoe_exposures (finding_id, repo_id, lockfile_id, version, first_seen, last_seen)
                VALUES (1, 1, 1, '0.1.1', 10, 10);
            SQL);
        $trigger = DB_DRIVER === 'mysql' ? '`trigger`' : '"trigger"';
        $this->pdo->exec("INSERT INTO gumshoe_runs (job, $trigger, started_at) VALUES
            ('gumshoe.inventory', 'cli', 20), ('gumshoe.osv-recheck', 'cli', 20)");
        $this->addLockfile(1, 1, 'package-lock.json');
    }

    public function testTruncatedTreeCannotFixAnExposure(): void
    {
        $this->inventory(false, []);
        $this->recordOtherwiseCompleteEvidence();
        self::assertSame([], $this->reconcile('partial'));
        $this->assertStillAffected();
    }

    public function testStaleLockfileCannotFixAnExposure(): void
    {
        $this->inventory(true, [[
            'path' => 'package-lock.json', 'kind' => 'npm', 'blob_sha' => str_repeat('b', 40),
            'parser_version' => 1, 'result' => new ParseResult([], 'parse_error'),
        ]]);
        self::assertSame('stale', $this->pdo->query('SELECT status FROM gumshoe_lockfiles')->fetchColumn());
        $this->recordOtherwiseCompleteEvidence();
        self::assertSame([], $this->reconcile('partial'));
        $this->assertStillAffected();
    }

    public function testBlob403MakesScanPartialAndKeepsExposure(): void
    {
        $branch = file_get_contents(__DIR__.'/fixtures/github/branch.json');
        $tree = json_encode(['truncated' => false, 'tree' => [[
            'path' => 'package-lock.json', 'type' => 'blob', 'mode' => '100644', 'sha' => str_repeat('a', 40),
        ]]], JSON_THROW_ON_ERROR);
        $transport = new FakeTransport([new Response(200, [], $branch), new Response(200, [], $tree), new Response(403)]);
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of(str_repeat('x', 24)));
        $tokens = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token');
        $scan = (new TreeReader(new Client($transport, 'https://example.org', $tokens)))->read(
            ['login' => 'octokit'], ['name' => 'rest.js', 'default_branch' => 'main'],
        );
        self::assertCount(3, $transport->requests);
        self::assertSame('partial', $scan['outcome']);
        (new InventoryStore($this->pdo))->apply(1, 1, $scan, new Policy());
        $this->recordOtherwiseCompleteEvidence();
        self::assertSame([], $this->reconcile($scan['outcome']));
        $this->assertStillAffected();
    }

    public static function unavailableOutcomes(): array
    {
        return ['inaccessible' => ['inaccessible'], 'out of watch' => ['out_of_watch']];
    }

    /** @dataProvider unavailableOutcomes */
    public function testUnavailableRepoBecomesUnknownOnce(string $outcome): void
    {
        $this->pdo->prepare('UPDATE gumshoe_repos SET outcome = ? WHERE id = 1')->execute([$outcome]);
        $this->pdo->exec('DELETE FROM gumshoe_deps');
        $transitions = $this->reconcile($outcome);
        self::assertSame($outcome, $transitions[1]['outcome'] ?? null);
        self::assertSame("octokit/rest.js is no longer scanned ($outcome); its status is unknown.", $transitions[1]['comment']);
        self::assertSame([], $this->reconcile($outcome));
        self::assertSame('unknown', $this->repoState(1)['state']);
        self::assertSame([1], $this->activeFlags());
        $this->assertFindingOpen();
    }

    public function testDisabledOwnerCannotFixAnExposureEvenWithACompleteOutcome(): void
    {
        $this->pdo->exec('UPDATE gumshoe_owners SET enabled = 0');
        $this->pdo->exec('DELETE FROM gumshoe_deps');
        self::assertSame([], $this->reconcile('complete'));
        $this->assertStillAffected();
    }

    public function testFailedOsvBatchCannotFixAnExposure(): void
    {
        $this->pdo->exec('DELETE FROM gumshoe_deps');
        $this->queue('0.1.1', 'pending', retryAt: 90);
        self::assertSame([], $this->reconcile('complete'));
        $this->assertStillAffected();
    }

    public function testUnfinishedReplacementVersionCannotFixAnExposure(): void
    {
        $this->pdo->exec("UPDATE gumshoe_deps SET version = '0.1.2'");
        $this->queue('0.1.2', 'pending', retryAt: 90);
        self::assertSame([], $this->reconcile('complete'));
        $this->assertStillAffected();
    }

    public function testIncompleteAdvisorySourcesCannotFixAnExposure(): void
    {
        $this->pdo->exec('DELETE FROM gumshoe_deps');
        self::assertSame([], $this->reconcile('complete', sourcesComplete: false));
        $this->assertStillAffected();
    }

    public function testLostPublicEvidenceCannotFixAnInstalledVersion(): void
    {
        $this->pdo->exec("UPDATE gumshoe_deps SET egress = 'denied'");
        self::assertSame([], $this->reconcile('complete'));
        $this->assertStillAffected();
    }

    public function testVersionStillInstalledAfterAdvisoryStopsMatchingIsNotFixed(): void
    {
        $this->queue('0.1.1', 'done');
        self::assertSame([], $this->reconcile('complete'));
        $this->assertStillAffected();
    }

    public function testPersistedPartialOutcomeOverridesCallerComplete(): void
    {
        $this->inventory(false, []);
        $this->recordOtherwiseCompleteEvidence();
        self::assertSame([], $this->reconcile('complete'));
        $this->assertStillAffected();
    }

    public function testPersistedCompleteOutcomeIsInsufficientWithoutFreshScanEvidence(): void
    {
        $this->pdo->exec('DELETE FROM gumshoe_deps');
        self::assertSame([], $this->reconcile(null));
        $this->assertStillAffected();
    }

    public function testHourlyRecheckCannotFixAnExposure(): void
    {
        $this->pdo->exec('DELETE FROM gumshoe_deps');
        $this->queue('0.1.1', 'done', runId: 2);
        self::assertSame([], $this->reconcile('complete', runId: 2));
        $this->assertStillAffected();
    }

    public function testCompleteScanAndAdvisoryAnswersCanFixAnExposure(): void
    {
        $this->pdo->exec("UPDATE gumshoe_deps SET version = '0.1.2'");
        $this->queue('0.1.2', 'done');
        self::assertSame('fixed', $this->reconcile('complete')[1]['to']);
        self::assertSame([], $this->reconcile('complete'));
        self::assertSame('fixed', $this->repoState(1)['state']);
        self::assertSame(7, (int) $this->repoState(1)['subtask_id']);
        self::assertSame([0], $this->activeFlags());
    }

    public function testUnfinishedQueryOfDifferentTypeDoesNotBlockFix(): void
    {
        $this->pdo->exec('DELETE FROM gumshoe_deps');
        $this->queue('0.1.1', 'pending', retryAt: 90);
        $this->pdo->exec("UPDATE gumshoe_pending SET query_type = 'commit'");
        self::assertSame('fixed', $this->reconcile('complete')[1]['to']);
    }

    public static function storedEmptyTreeOutcomes(): array
    {
        return ['inventory store' => ['complete'], 'explicit empty tree outcome' => ['no_lockfile']];
    }

    /** @dataProvider storedEmptyTreeOutcomes */
    public function testCompleteTreeWithDeletedLockfileCanFixAnExposure(string $storedOutcome): void
    {
        (new InventoryStore($this->pdo))->apply(1, 1, [
            'outcome' => 'no_lockfile', 'treeComplete' => true, 'headSha' => null, 'treeSha' => null, 'files' => [],
        ], new Policy());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_deps')->fetchColumn());
        if ($storedOutcome === 'no_lockfile') {
            $this->pdo->exec("UPDATE gumshoe_repos SET outcome = 'no_lockfile' WHERE id = 1");
        }
        self::assertSame('fixed', $this->reconcile('no_lockfile')[1]['to']);
        self::assertSame([0], $this->activeFlags());
    }

    public function testMergedFindingMovesToFinalSurvivorWithoutFixingInstalledVersion(): void
    {
        $this->addLockfile(2, 2, 'package-lock.json');
        $this->queue('0.1.1', 'done');
        $this->pdo->exec(<<<'SQL'
            INSERT INTO gumshoe_groups (id, primary_id, merged_into) VALUES
                (2, 'CVE-2018-16492', NULL), (3, 'GHSA-mh6f-8j2x-4483', 2);
            UPDATE gumshoe_groups SET merged_into = 3 WHERE id = 1;
            INSERT INTO gumshoe_findings (id, group_id, ecosystem, package, status, task_id)
                VALUES (2, 2, 'npm', 'flatmap-stream', 'dismissed', 11);
            INSERT INTO gumshoe_finding_repos (finding_id, repo_id, subtask_id, state, ever_affected)
                VALUES (2, 1, 8, 'unknown', 0), (1, 2, 9, 'unknown', 1);
            INSERT INTO gumshoe_exposures (finding_id, repo_id, lockfile_id, version, active, first_seen, last_seen)
                VALUES (2, 1, 1, '0.1.1', 0, 5, 15), (1, 2, 2, '0.1.1', 1, 11, 12);
            SQL);

        $transitions = $this->reconcile('complete');
        self::assertSame(['open', 'merged', 2], [
            $transitions[1]['from'], $transitions[1]['to'], $transitions[1]['survivor_finding_id'],
        ]);
        self::assertSame(['merged', 'open'], $this->pdo->query(
            'SELECT status FROM gumshoe_findings ORDER BY id',
        )->fetchAll(PDO::FETCH_COLUMN));
        self::assertSame(11, (int) $this->pdo->query('SELECT task_id FROM gumshoe_findings WHERE id = 2')->fetchColumn());
        self::assertSame(['affected', 'unknown'], array_column([$this->repoState(1, 2), $this->repoState(2, 2)], 'state'));
        self::assertSame(1, (int) $this->repoState(2, 2)['ever_affected']);
        self::assertSame(8, (int) $this->repoState(1, 2)['subtask_id']);
        self::assertSame(0, (int) $this->repoState(2, 2)['subtask_id']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_finding_repos WHERE finding_id = 1')->fetchColumn());
        self::assertSame([1, 1], $this->activeFlags());
        self::assertSame([2, 2], array_map('intval', $this->pdo->query(
            'SELECT finding_id FROM gumshoe_exposures ORDER BY lockfile_id',
        )->fetchAll(PDO::FETCH_COLUMN)));
        self::assertEquals([5, 15], $this->pdo->query(
            'SELECT first_seen, last_seen FROM gumshoe_exposures WHERE lockfile_id = 1',
        )->fetch(PDO::FETCH_NUM));
        self::assertSame([], $this->reconcile('complete'));
    }

    public function testMergeCreatesMissingSurvivorFinding(): void
    {
        $this->pdo->exec(<<<'SQL'
            INSERT INTO gumshoe_groups (id, primary_id) VALUES (2, 'CVE-2018-16492');
            UPDATE gumshoe_groups SET merged_into = 2 WHERE id = 1;
            SQL);
        $transitions = $this->reconcile(null, runId: 2);
        $survivor = $transitions[1]['survivor_finding_id'];
        self::assertSame('merged', $transitions[1]['to']);
        self::assertSame('affected', $this->repoState(1, $survivor)['state']);
        self::assertSame([1], $this->activeFlags());
    }

    public function testRepoIsFixedOnlyAfterAllItsLockfilesAreFixed(): void
    {
        $this->addLockfile(2, 1, 'tools/package-lock.json');
        $this->pdo->exec("INSERT INTO gumshoe_exposures
            (finding_id, repo_id, lockfile_id, version, first_seen, last_seen) VALUES (1, 1, 2, '0.1.1', 10, 10)");
        $this->pdo->exec('DELETE FROM gumshoe_deps WHERE lockfile_id = 1');
        $this->queue('0.1.1', 'done');
        self::assertSame([], $this->reconcile('complete', [$this->match(1, 2)]));
        self::assertSame('affected', $this->repoState(1)['state']);
        self::assertSame([0, 1], $this->activeFlags());

        $this->pdo->exec('DELETE FROM gumshoe_deps WHERE lockfile_id = 2');
        self::assertSame('fixed', $this->reconcile('complete')[1]['to']);
        self::assertSame([0, 0], $this->activeFlags());
    }

    public function testPositiveMatchAddsNewRepoOnHourlyRecheckWithoutChangingExistingRepo(): void
    {
        $this->addLockfile(2, 2, 'package-lock.json');
        $transitions = $this->reconcile(null, [$this->match(2, 2)], runId: 2, repoId: 2, sourcesComplete: false);
        self::assertSame('affected', $transitions[1]['to']);
        self::assertFalse($transitions[1]['was_ever_affected']);
        self::assertSame('affected', $this->repoState(2)['state']);
        self::assertSame(1, (int) $this->repoState(2)['ever_affected']);
        self::assertSame('affected', $this->repoState(1)['state']);
        self::assertSame([], $this->reconcile(null, [$this->match(2, 2)], runId: 2, repoId: 2));
        self::assertSame([1, 1], $this->activeFlags());
    }

    private function reconcile(
        ?string $outcome,
        array $matches = [],
        int $runId = 1,
        int $repoId = 1,
        bool $sourcesComplete = true,
    ): array {
        return (new Reconciler(new FindingModel($this->pdo)))->apply($runId, $repoId, $outcome, $matches, $sourcesComplete, 20);
    }

    private function assertStillAffected(): void
    {
        self::assertSame('affected', $this->repoState(1)['state']);
        self::assertSame([1], $this->activeFlags());
        $this->assertFindingOpen();
    }

    private function assertFindingOpen(): void
    {
        self::assertSame('open', $this->pdo->query('SELECT status FROM gumshoe_findings WHERE id = 1')->fetchColumn());
    }

    private function repoState(int $repoId, int $findingId = 1): array
    {
        $stmt = $this->pdo->prepare('SELECT * FROM gumshoe_finding_repos WHERE finding_id = ? AND repo_id = ?');
        $stmt->execute([$findingId, $repoId]);
        return $stmt->fetch(PDO::FETCH_ASSOC);
    }

    private function activeFlags(): array
    {
        return array_map('intval', $this->pdo->query('SELECT active FROM gumshoe_exposures ORDER BY lockfile_id')->fetchAll(PDO::FETCH_COLUMN));
    }

    private function inventory(bool $treeComplete, array $files): void
    {
        (new InventoryStore($this->pdo))->apply(1, 1, [
            'treeComplete' => $treeComplete, 'headSha' => null, 'treeSha' => null, 'files' => $files,
        ], new Policy());
        self::assertSame('partial', $this->pdo->query('SELECT outcome FROM gumshoe_repos WHERE id = 1')->fetchColumn());
    }

    private function recordOtherwiseCompleteEvidence(): void
    {
        // Remove the independent blockers to test the outcome gate on its own.
        $this->pdo->exec("UPDATE gumshoe_lockfiles SET status = 'ok' WHERE repo_id = 1");
        $this->pdo->exec('DELETE FROM gumshoe_deps WHERE lockfile_id = 1');
        $this->queue('0.1.1', 'done');
    }

    private function addLockfile(int $id, int $repoId, string $path): void
    {
        $this->pdo->prepare("INSERT INTO gumshoe_lockfiles (id, repo_id, path_hash, path, blob_sha, kind, status, parser_version)
            VALUES (?, ?, ?, ?, ?, 'npm', 'ok', 1)")->execute([$id, $repoId, hash('sha256', $path), $path, str_repeat('a', 40)]);
        $this->pdo->prepare("INSERT INTO gumshoe_deps (lockfile_id, ecosystem, name, version, scope, query_type, egress)
            VALUES (?, 'npm', 'flatmap-stream', '0.1.1', 'prod', 'package', 'public')")->execute([$id]);
    }

    private function queue(string $version, string $state, ?int $retryAt = null, int $runId = 1): void
    {
        $this->pdo->prepare("INSERT INTO gumshoe_pending (run_id, query_type, ecosystem, name, version, egress, state, retry_at)
            VALUES (?, 'package', 'npm', 'flatmap-stream', ?, 'public', ?, ?)")->execute([$runId, $version, $state, $retryAt]);
    }

    private function match(int $repoId, int $lockfileId): array
    {
        return [
            'group_id' => 1, 'ecosystem' => 'npm', 'package' => 'flatmap-stream',
            'repo_id' => $repoId, 'lockfile_id' => $lockfileId, 'version' => '0.1.1',
        ];
    }
}
