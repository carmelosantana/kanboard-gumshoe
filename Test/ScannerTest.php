<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Http\Transport;
use Kanboard\Plugin\Gumshoe\Run\Jobs;
use Kanboard\Plugin\Gumshoe\Run\RunLog;
use Kanboard\Plugin\Gumshoe\Run\Scanner;
use Kanboard\Plugin\Gumshoe\Run\WriterLease;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeVaultSecrets;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use KanboardTests\units\Base;
use PDO;
use RuntimeException;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/ReleasesConnection.php';
require_once __DIR__.'/Fakes/FakeVaultSecrets.php';

final class ScannerTest extends Base
{
    use ReleasesConnection;

    private const INVENTORY = 'gumshoe.inventory';
    private const RECHECK = 'gumshoe.osv-recheck';
    private const ADVISORY = 'GHSA-mh6f-8j2x-4483';
    private const SHA = '11bd71901bbe5b1630ceea73d27597364c9af683';
    private PDO $pdo;
    private int $now = 1_800_000_000;
    private array $requests = [];
    private array $phases = [];
    private string $version = '0.1.1';
    private bool $vulnerable = true;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $this->pdo = $this->container['db']->getConnection();
        version_1($this->pdo);
        $this->pdo->exec("INSERT INTO gumshoe_owners (login, kind, token_ref) VALUES ('symfony', 'org', 'vault://17/token')");
        $project = $this->container['projectModel']->create(['name' => 'Findings']);
        $this->pdo->exec('UPDATE gumshoe_settings SET project_id = '.(int) $project);
        $this->container['vaultSecrets'] = new FakeVaultSecrets(static fn () => SecretValue::of(bin2hex(random_bytes(20))));
    }

    public function testDiscoveryRestartsAtPageOneAndChecksTheDeadlineBeforePageTwo(): void
    {
        $pageOne = 'https://api.github.com/orgs/symfony/repos?type=all';
        $pageTwo = 'https://api.github.com/organizations/17/repos?type=all&page=2';
        $deadline = $this->now + 1;
        $scanner = $this->scanner(function (Request $request) use ($pageOne, $pageTwo, $deadline): Response {
            if ($request->url === $pageOne) {
                $this->now = $deadline;
                return new Response(200, ['Link' => "<$pageTwo>; rel=\"next\""], $this->listing()->body);
            }
            return $this->respond($request);
        });

        self::assertSame('more', $scanner->tick(self::INVENTORY, 'foreman', $deadline)['status']);
        self::assertSame([$pageOne], array_column($this->requests, 'url'));
        self::assertSame('discover', $this->latest()['phase']);
        self::assertSame('1', $this->latest()['position']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_repos')->fetchColumn());

        $scanner = $this->scanner(fn (Request $request): Response => match ($request->url) {
            $pageOne => new Response(200, ['Link' => "<$pageTwo>; rel=\"next\""], $this->listing()->body),
            $pageTwo => new Response(200, [], '[]'),
            default => $this->respond($request),
        });
        self::assertSame('done', $scanner->tick(self::INVENTORY, 'foreman')['status'], json_encode([$this->latest(), array_column($this->requests, 'operation')]));
        self::assertSame([$pageOne, $pageOne, $pageTwo], array_slice(array_column($this->requests, 'url'), 0, 3));
        self::assertSame('done', $this->latest()['phase']);
        self::assertSame([['Gumshoe', 'vault://17/token', 'gumshoe.inventory']], array_slice($this->container['vaultSecrets']->reads, 0, 1));
        self::assertCount(2, $this->container['vaultSecrets']->reads);
    }

    public function testPendingWorkSurvivesInterruptionAndUnchangedTriplesAreRequeued(): void
    {
        $scanner = $this->scanner(function (Request $request): Response {
            if ($request->operation === 'osv.querybatch') {
                throw new RuntimeException('Interrupted after inventory');
            }
            return $this->respond($request);
        });
        self::assertSame('more', $scanner->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame(['discover', 'inventory', 'inventory', 'inventory', 'query'], $this->phases);
        $interrupted = $this->latest();
        self::assertSame('query', $interrupted['phase']);
        self::assertSame('pending', $this->pdo->query('SELECT state FROM gumshoe_pending')->fetchColumn());
        self::assertSame('flatmap-stream', $this->pdo->query('SELECT name FROM gumshoe_pending')->fetchColumn());
        $this->now = (int) $interrupted['retry_at'];
        $this->requests = [];
        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame('osv.querybatch', $this->requests[0]->operation);
        self::assertSame($interrupted['id'], $this->latest()['id']);
        self::assertSame('affected', $this->repoState());
        self::assertSame('open', $this->findingStatus());
        self::assertSame('high', $this->pdo->query('SELECT priority FROM gumshoe_findings')->fetchColumn());
        self::assertSame(9.8, (float) $this->pdo->query('SELECT cvss_max FROM gumshoe_groups')->fetchColumn());

        $this->vulnerable = false;
        $this->requests = [];
        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame(['gh.list', 'gh.branch'],
            array_values(array_filter(array_column($this->requests, 'operation'), static fn (string $op): bool =>
                in_array($op, ['gh.list', 'gh.branch', 'gh.tree', 'gh.blob'], true))));
        self::assertStringContainsString('"version":"0.1.1"', $this->osvRequestBody());
        self::assertSame('affected', $this->repoState());

        $this->version = '0.1.2';
        $this->pdo->exec("UPDATE gumshoe_deps SET version = '0.1.2'");
        self::assertSame('done', $this->scanner()->tick(self::RECHECK, 'cli')['status']);
        self::assertSame('affected', $this->repoState());
        $this->requests = [];
        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'cli')['status']);
        self::assertStringContainsString('"version":"0.1.2"', $this->osvRequestBody());
        self::assertSame('fixed', $this->repoState());
        self::assertSame('fixed', $this->findingStatus());
    }

    public function testChangedHeadReusesUnchangedBlobsUntilTheParserVersionChanges(): void
    {
        $head = self::SHA;
        $composer = sha1('composer.lock');
        $pnpm = sha1('pnpm-lock.yaml');
        $registry = sha1('.npmrc');
        $responder = function (Request $request) use (&$head, &$composer, $pnpm, &$registry): Response {
            return match ($request->operation) {
                'gh.branch' => self::json(['commit' => ['sha' => $head, 'commit' => ['tree' => ['sha' => $head]]]]),
                'gh.tree' => self::json(['truncated' => false, 'tree' => [
                    ['path' => 'composer.lock', 'sha' => $composer, 'type' => 'blob', 'mode' => '100644'],
                    ['path' => 'pnpm-lock.yaml', 'sha' => $pnpm, 'type' => 'blob', 'mode' => '100644'],
                    ['path' => '.npmrc', 'sha' => $registry, 'type' => 'blob', 'mode' => '100644'],
                ]]),
                'gh.blob' => match (basename($request->url)) {
                    $composer => self::json(['packages' => []]),
                    $pnpm => new Response(200, [], "lockfileVersion: '9.0'\npackages:\n  is-number@6.0.0: {}\n"),
                    $registry => new Response(200, [], $registry === sha1('.npmrc')
                        ? 'registry=https://registry.npmjs.org/' : 'registry=https://example.org/'),
                },
                'osv.querybatch' => self::json(['results' => [(object) []]]),
                default => $this->respond($request),
            };
        };
        $scan = function () use ($responder): array {
            $this->requests = [];
            self::assertSame('done', $this->scanner($responder)->tick(self::INVENTORY, 'cli')['status']);
            self::assertSame('complete', $this->pdo->query('SELECT outcome FROM gumshoe_repos')->fetchColumn());
            return array_map(static fn (Request $request): string => basename($request->url),
                array_values(array_filter($this->requests, static fn (Request $request): bool => $request->operation === 'gh.blob')));
        };

        self::assertSame([$composer, $pnpm, $registry], $scan());
        $deps = $this->pdo->query('SELECT * FROM gumshoe_deps')->fetchAll(PDO::FETCH_ASSOC);
        $head = sha1('composer changed');
        $composer = sha1('new composer.lock');
        self::assertSame([$composer], $scan());
        self::assertSame($deps, $this->pdo->query('SELECT * FROM gumshoe_deps')->fetchAll(PDO::FETCH_ASSOC));
        self::assertStringContainsString('"name":"is-number"', $this->osvRequestBody());

        $head = sha1('registry changed');
        $registry = sha1('new .npmrc');
        self::assertSame([$registry], $scan());
        self::assertSame('private', $this->pdo->query('SELECT egress FROM gumshoe_deps')->fetchColumn());
        self::assertNotContains('osv.querybatch', array_column($this->requests, 'operation'));

        $old = (int) $this->pdo->query("SELECT parser_version FROM gumshoe_lockfiles WHERE kind = 'pnpm'")->fetchColumn() - 1;
        $this->pdo->exec("UPDATE gumshoe_lockfiles SET parser_version = $old WHERE kind = 'pnpm'");
        self::assertSame([$pnpm], $scan());
        self::assertSame($old + 1, (int) $this->pdo->query("SELECT parser_version FROM gumshoe_lockfiles WHERE kind = 'pnpm'")->fetchColumn());
    }

    public function testOsvCommitsEachBatchBeforeFetchingTheNext(): void
    {
        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'cli')['status']);
        $file = (int) $this->pdo->query('SELECT id FROM gumshoe_lockfiles')->fetchColumn();
        $insert = $this->pdo->prepare("INSERT INTO gumshoe_deps
            (lockfile_id, ecosystem, name, version, scope, query_type, egress)
            VALUES (?, 'npm', 'lodash', ?, 'prod', 'package', 'public')");
        for ($i = 0; $i < 2000; $i++) {
            $insert->execute([$file, '4.17.20-build.'.$i]);
        }

        $calls = 0;
        $scanner = $this->scanner(function (Request $request) use (&$calls): Response {
            self::assertSame('osv.querybatch', $request->operation);
            if (++$calls === 3) {
                throw new RuntimeException('Interrupted before the third batch.');
            }
            return self::json(['results' => array_fill(0, 1000, (object) [])]);
        });
        self::assertSame('more', $scanner->tick(self::RECHECK, 'cli')['status']);
        self::assertSame(3, $calls);
        self::assertSame(2000, (int) $this->pdo->query("SELECT COUNT(*) FROM gumshoe_pending WHERE state = 'done'")->fetchColumn());
        self::assertSame(1, (int) $this->pdo->query("SELECT COUNT(*) FROM gumshoe_pending WHERE state = 'pending'")->fetchColumn());

        $recheck = (new RunLog($this->pdo))->latest(self::RECHECK);
        $this->now = (int) $recheck['retry_at'];
        $scanner = $this->scanner(function (Request $request): Response {
            self::assertCount(1, json_decode($request->body, true)['queries']);
            return self::json(['results' => [(object) []]]);
        });
        self::assertSame('done', $scanner->tick(self::RECHECK, 'cli')['status']);
    }

    public function testMalwarePaginationResumesAtThePersistedCursor(): void
    {
        $first = 'https://api.github.com/advisories?type=malware&ecosystem=npm&per_page=100';
        $second = $first.'&after=Y3Vyc29y%3D';
        $catalog = json_decode(file_get_contents(__DIR__.'/fixtures/ghsa/malware-npm.json'), true, flags: JSON_THROW_ON_ERROR);
        $file = function (Request $request) use ($first, $second, $catalog): Response {
            if ($request->url === $first) {
                $this->now++;
                return new Response(200, ['Link' => "<$second>; rel=next"], json_encode(array_slice($catalog, 0, 2)));
            }
            if ($request->url === $second) {
                $this->now++;
                return self::json(array_slice($catalog, 2));
            }
            return $this->respond($request);
        };
        self::assertSame('more', $this->scanner($file)->tick(self::INVENTORY, 'foreman', $this->now + 1)['status']);
        self::assertSame('query', $this->latest()['phase']);
        self::assertSame($second, $this->latest()['position']);

        $chunks = fn (): array => $this->pdo->query("SELECT advisory_id, body FROM gumshoe_advisory_cache
            WHERE source = 'run-malware' AND advisory_id LIKE '%:%' ORDER BY advisory_id")->fetchAll(PDO::FETCH_KEY_PAIR);
        $firstPage = $chunks();
        self::assertCount(1, $firstPage);
        $this->requests = [];
        self::assertSame('more', $this->scanner($file)->tick(self::INVENTORY, 'foreman', $this->now + 1)['status']);
        self::assertSame([$second], array_column($this->requests, 'url'));
        self::assertCount(2, $chunks());
        self::assertSame($firstPage, array_intersect_key($chunks(), $firstPage));

        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'foreman')['status']);
        self::assertNotContains($first, array_column($this->requests, 'url'));
        self::assertSame(count($catalog), (int) $this->pdo
            ->query("SELECT COUNT(*) FROM gumshoe_advisory_cache WHERE source = 'github-malware'")->fetchColumn());
        self::assertSame(0, (int) $this->pdo
            ->query("SELECT COUNT(*) FROM gumshoe_advisory_cache WHERE source = 'run-malware'")->fetchColumn());
    }

    public function testInventoryResumesARepositoryWithOneRequestPerSlice(): void
    {
        $blobShas = array_map(static fn (int $i): string => sha1('composer-lock-'.$i), range(1, 4));
        $response = function (Request $request) use ($blobShas): Response {
            $this->now++;
            return match ($request->operation) {
                'gh.tree' => self::json(['truncated' => false, 'tree' => array_map(
                    static fn (int $index, string $sha): array => [
                        'path' => 'packages/'.($index + 1).'/composer.lock', 'type' => 'blob',
                        'mode' => '100644', 'sha' => $sha, 'size' => 1024,
                    ],
                    array_keys($blobShas), $blobShas,
                )]),
                'gh.blob' => new Response(200, [], '{"packages":[]}'),
                default => $this->respond($request),
            };
        };
        foreach (['gh.list', 'gh.branch', 'gh.tree', ...array_fill(0, 4, 'gh.blob')] as $operation) {
            $this->requests = [];
            self::assertSame('more', $this->scanner($response)->tick(self::INVENTORY, 'foreman', $this->now + 1)['status']);
            self::assertSame([$operation], array_column($this->requests, 'operation'));
        }
        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'foreman')['status']);
        self::assertSame('complete', $this->pdo->query('SELECT outcome FROM gumshoe_repos')->fetchColumn());
        self::assertSame($blobShas, $this->pdo->query('SELECT blob_sha FROM gumshoe_lockfiles ORDER BY path')->fetchAll(PDO::FETCH_COLUMN));
    }

    public function testTerminalRunsFreePendingRowsAndKeepOneAnswerPerIdentity(): void
    {
        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_pending')->fetchColumn());
        $this->vulnerable = false;
        self::assertSame('done', $this->scanner()->tick(self::RECHECK, 'cli')['status']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_pending')->fetchColumn());
        self::assertSame(['[]'], $this->pdo->query("SELECT body FROM gumshoe_advisory_cache WHERE source = 'osv-query'")->fetchAll(PDO::FETCH_COLUMN));
    }

    public function testDiscoveryUnitWithoutProgressFailsAfterThreeSlices(): void
    {
        $scanner = $this->scanner(function (Request $request): Response {
            $this->now++;
            return new Response(200, [
                'Link' => '<https://api.github.com/organizations/17/repos?type=all&page=2>; rel="next"',
            ], $this->listing()->body);
        });
        foreach (['more', 'more', 'more', 'failed'] as $status) {
            self::assertSame($status, $scanner->tick(self::INVENTORY, 'foreman', $this->now + 1)['status']);
        }
        self::assertSame('discover', $this->latest()['phase']);
        self::assertSame('1', $this->latest()['position']);
    }

    /** @dataProvider unexpectedFailureRecovery */
    public function testUnexpectedExceptionsHaveTheirOwnRetryBudget(bool $recover): void
    {
        $throwOnNextClockRead = false;
        $httpFails = false;
        $scanner = $this->scanner(
            function (Request $request) use (&$throwOnNextClockRead, &$httpFails): Response {
                if ($request->operation === 'gh.advisories') {
                    if ($httpFails) {
                        return new Response(503);
                    }
                    $throwOnNextClockRead = true;
                }
                return $this->respond($request);
            },
            function () use (&$throwOnNextClockRead): int {
                if ($throwOnNextClockRead) {
                    $throwOnNextClockRead = false;
                    throw new \LogicException('internal exception message');
                }
                return $this->now;
            },
        );
        self::assertSame('more', $scanner->tick(self::INVENTORY, 'cli')['status']);
        $run = $this->latest();
        self::assertNull($run['exception_class']);
        self::assertStringNotContainsString('internal exception message', json_encode($run));
        $this->now = (int) $run['retry_at'];
        $httpFails = $recover;
        self::assertSame('more', $scanner->tick(self::INVENTORY, 'cli')['status']);
        $this->now = (int) $this->latest()['retry_at'];
        self::assertSame('failed', $scanner->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame($run['id'], $this->latest()['id']);
        self::assertSame($recover ? \Kanboard\Plugin\Gumshoe\Http\HttpFailure::class : \LogicException::class,
            $this->latest()['exception_class']);
    }

    public static function unexpectedFailureRecovery(): iterable
    {
        yield 'three unexpected failures' => [false];
        yield 'HTTP still gets its retry after an unexpected exception' => [true];
    }

    public function testDisabledJobsAndHourlyRecheckWithoutGithub(): void
    {
        $jobs = (new Jobs($this->scanner()))->descriptors();
        self::assertSame([self::INVENTORY, self::RECHECK], array_column($jobs, 'id'));
        self::assertSame([86400, 3600], array_column($jobs, 'interval'));
        $this->pdo->exec('UPDATE gumshoe_settings SET scanning = 0');
        foreach ($jobs as $job) {
            self::assertSame('done', $job['run']($this->now + $job['budget'])['status']);
        }
        $this->pdo->exec('UPDATE gumshoe_settings SET scanning = 1, hourly = 0');
        self::assertSame('done', $jobs[1]['run']($this->now + 10)['status']);
        self::assertSame([], $this->requests);
        self::assertSame([], (new RunLog($this->pdo))->recent());

        self::assertSame('done', $jobs[0]['run']($this->now + 10)['status']);
        $this->pdo->exec('UPDATE gumshoe_settings SET hourly = 1');
        $this->pdo->prepare("INSERT INTO gumshoe_deps (lockfile_id, ecosystem, name, version, scope, query_type, egress)
            SELECT id, 'actions', 'actions/checkout', ?, 'action', 'commit', 'public' FROM gumshoe_lockfiles")
            ->execute([self::SHA]);
        $this->requests = [];
        self::assertSame('done', $jobs[1]['run']($this->now + 10)['status']);
        self::assertSame(['osv.querybatch'], array_column($this->requests, 'operation'));
        self::assertSame(['queries' => [['package' => ['ecosystem' => 'npm', 'name' => 'flatmap-stream'], 'version' => '0.1.1']]],
            json_decode($this->osvRequestBody(), true));
    }

    public function testQueryAndSyncPublishTheirCurrentPositionsBeforeWork(): void
    {
        $positions = [];
        $this->container['hook']->on('model:task:creation:aftersave', function () use (&$positions): void {
            $positions['sync'] = $this->latest()['position'];
        });
        $scanner = $this->scanner(function (Request $request) use (&$positions): Response {
            if ($request->operation === 'osv.querybatch') {
                $positions['query'] = $this->latest()['position'];
            }
            return $this->respond($request);
        });
        self::assertSame('done', $scanner->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame(['query' => '1', 'sync' => '1'], $positions);
    }

    public function testBoardSyncVisitsTheSurvivorWithItsOwnCheckpoint(): void
    {
        $this->pdo->exec("INSERT INTO gumshoe_groups (primary_id, merged_into) VALUES
            ('GHSA-mh6f-8j2x-4483', NULL), ('CVE-2018-16492', 1)");
        $this->pdo->exec("INSERT INTO gumshoe_group_aliases (alias, group_id) VALUES ('GHSA-mh6f-8j2x-4483', 1)");
        $this->pdo->exec("INSERT INTO gumshoe_findings (group_id, ecosystem, package, status) VALUES
            (2, 'npm', 'flatmap-stream', 'merged'), (1, 'npm', 'flatmap-stream', 'open')");
        $positions = [];
        $this->container['hook']->on('model:task:creation:aftersave', function () use (&$positions): void {
            $positions[] = $this->latest()['position'];
        });

        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame(['2'], $positions);
        self::assertSame('affected', $this->repoState());
    }

    public function testDenyPrefixAddedAfterQueueingPreventsSendingThePendingTriple(): void
    {
        $scanner = $this->scanner(function (Request $request): Response {
            if ($request->operation === 'osv.querybatch') {
                return new Response(503, ['Retry-After' => '120']);
            }
            return $this->respond($request);
        });
        self::assertSame('more', $scanner->tick(self::INVENTORY, 'foreman')['status']);
        self::assertSame('pending', $this->pdo->query('SELECT state FROM gumshoe_pending')->fetchColumn());
        $this->now = (int) $this->latest()['retry_at'];
        $this->pdo->exec("UPDATE gumshoe_settings SET deny_prefixes = 'flatmap-'");
        $this->requests = [];
        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'foreman')['status']);
        self::assertNotContains('osv.querybatch', array_column($this->requests, 'operation'));
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_findings')->fetchColumn());
    }

    /** @dataProvider upstreamFailures */
    public function testSourceFailuresBackOffAndStoreOnlyExceptionClass(string $operation): void
    {
        $scanner = $this->scanner(fn (Request $request): Response => $request->operation === $operation
            ? new Response(503, ['Retry-After' => '120'], 'upstream diagnostic')
            : $this->respond($request));
        self::assertSame('more', $scanner->tick(self::INVENTORY, 'foreman')['status']);
        $run = $this->latest();
        self::assertGreaterThanOrEqual($this->now + 60, (int) $run['retry_at']);
        $count = count($this->requests);
        self::assertSame('more', $scanner->tick(self::INVENTORY, 'foreman')['status']);
        self::assertCount($count, $this->requests);
        $this->now = (int) $run['retry_at'];
        $result = $scanner->tick(self::INVENTORY, 'foreman');
        self::assertSame('failed', $result['status']);
        self::assertSame($run['id'], $this->latest()['id']);
        self::assertSame('failed', $this->latest()['status']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_pending')->fetchColumn());
        self::assertSame(\Kanboard\Plugin\Gumshoe\Http\HttpFailure::class, $this->latest()['exception_class']);
        self::assertStringNotContainsString('upstream diagnostic', json_encode([$result, $this->latest()]));
    }

    public static function upstreamFailures(): iterable
    {
        foreach (['gh.list', 'osv.querybatch', 'gh.advisories', 'kev'] as $operation) {
            yield $operation => [$operation];
        }
    }

    public function testForemanRetryWaitUsesTheTriggerAndLeavesTheWriterFree(): void
    {
        $log = new RunLog($this->pdo);
        $id = (int) $log->start(self::INVENTORY, 'foreman', 'discover', $this->now)['id'];
        $retryAt = $this->now + 60;
        $log->defer($id, $retryAt);
        $sleeps = [];
        $lease = new WriterLease($this->pdo, fn (): int => $this->now);
        $scanner = $this->scanner(sleeper: static function (int $seconds) use (&$sleeps, $lease): void {
            self::assertTrue($lease->claim('waiting-test', 60));
            self::assertTrue($lease->release('waiting-test'));
            $sleeps[] = $seconds;
        });
        $job = (new Jobs($scanner))->descriptors()[0]['run'];
        $waiting = ['status' => 'more', 'summary' => 'waiting for retry at '.date('H:i', $retryAt)];
        self::assertSame($waiting, $job($this->now + 10, 'web'));
        self::assertSame([], $sleeps);
        self::assertSame($waiting, $job($this->now + 10, 'cli'));
        self::assertSame($waiting, $job($this->now + 2, 'cli'));
        $log->defer($id, $this->now + 1);
        self::assertSame('more', $job($this->now + 10, 'cli')['status']);
        self::assertSame([5, 2, 1], $sleeps);
        self::assertSame([], $this->requests);

        $log->finish($id, 'failed', $this->now, retryAt: $retryAt);
        self::assertSame('done', $job($this->now + 10, 'cli')['status']);
        self::assertSame([5, 2, 1], $sleeps);
        self::assertCount(1, $log->recent());
    }

    public function testBothJobsReturnMoreWhileAnotherWriterHoldsTheLease(): void
    {
        $lease = new WriterLease($this->pdo, fn (): int => $this->now);
        self::assertTrue($lease->claim('other-writer', 60));
        $sleeps = [];
        $scanner = $this->scanner(sleeper: static function (int $seconds) use (&$sleeps): void {
            $sleeps[] = $seconds;
        });
        self::assertSame('more', $scanner->tick(self::INVENTORY, 'web')['status']);
        self::assertSame([], $sleeps);
        self::assertSame('more', $scanner->tick(self::RECHECK, 'cli', $this->now + 2)['status']);
        self::assertSame([2], $sleeps);
        self::assertSame([], $this->requests);
        self::assertSame([], (new RunLog($this->pdo))->recent());
        self::assertTrue($lease->release('other-writer'));
    }

    public function testCliWaitsForTheOtherJobWithoutHoldingTheLease(): void
    {
        $log = new RunLog($this->pdo);
        $run = $log->start(self::INVENTORY, 'web', 'discover', $this->now);
        $sleeps = [];
        $lease = new WriterLease($this->pdo, fn (): int => $this->now);
        $scanner = $this->scanner(sleeper: static function (int $seconds) use (&$sleeps, $lease): void {
            self::assertTrue($lease->claim('waiting-test', 60));
            self::assertTrue($lease->release('waiting-test'));
            $sleeps[] = $seconds;
        });
        self::assertSame('more', $scanner->tick(self::RECHECK, 'web')['status']);
        self::assertSame([], $sleeps);
        self::assertSame('more', $scanner->tick(self::RECHECK, 'cli')['status']);
        self::assertSame([5], $sleeps);
        self::assertSame([], $this->requests);
        self::assertSame([$run], $log->recent());
    }

    /** @dataProvider vaultPrerequisites */
    public function testJobsDoNoWorkWithoutVaultAndAnEnabledOwnerWithARef(string $missing): void
    {
        match ($missing) {
            'api' => $this->removeVault(),
            'sharing' => $this->container['vaultSecrets']->ready = false,
            'ref' => $this->pdo->exec("UPDATE gumshoe_owners SET token_ref = NULL"),
            'enabled' => $this->pdo->exec("UPDATE gumshoe_owners SET enabled = 0"),
        };
        $scanner = $this->scanner();
        foreach ([self::INVENTORY, self::RECHECK] as $job) {
            self::assertSame('done', $scanner->tick($job, 'foreman')['status']);
        }
        self::assertSame([], $this->requests);
        self::assertSame([], (new RunLog($this->pdo))->recent());
    }

    public static function vaultPrerequisites(): iterable
    {
        foreach (['api', 'sharing', 'ref', 'enabled'] as $missing) {
            yield $missing => [$missing];
        }
    }

    private function removeVault(): void
    {
        unset($this->container['vaultSecrets']);
    }

    public function testMissingOwnerTokenPreservesItsRepoAndLetsTheRunSucceed(): void
    {
        $this->pdo->exec("INSERT INTO gumshoe_owners (login, kind) VALUES ('php', 'org')");
        $this->pdo->exec("INSERT INTO gumshoe_repos (owner_id, name, github_id, mode, outcome, last_complete_at)
            SELECT id, 'php-src', 2, 'pin', 'complete', 1 FROM gumshoe_owners WHERE login = 'php'");

        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'foreman')['status']);
        $run = $this->latest();
        self::assertSame('ok', $run['status']);
        self::assertNull($run['retry_at']);
        self::assertNull($run['exception_class']);
        $counts = json_decode($run['counts'], true);
        self::assertCount(1, $counts['failed_owners']);
        self::assertSame(1, $counts['complete']);
        self::assertSame(['php-src' => 'complete', 'yaml' => 'complete'], $this->pdo
            ->query('SELECT name, outcome FROM gumshoe_repos ORDER BY name')->fetchAll(PDO::FETCH_KEY_PAIR));
        self::assertSame(1, (int) $this->pdo->query("SELECT last_complete_at FROM gumshoe_repos WHERE name = 'php-src'")->fetchColumn());
        self::assertSame('missing', $this->pdo->query("SELECT token_status FROM gumshoe_owners WHERE login = 'php'")->fetchColumn());
    }

    public function testOwnerListingFailureAfterRetryFailsEvenWhenTheOtherOwnerWasScanned(): void
    {
        $this->pdo->exec("INSERT INTO gumshoe_owners (login, kind, token_ref) VALUES ('php', 'org', 'vault://18/token')");
        $scanner = $this->scanner(fn (Request $request): Response => $request->operation === 'gh.list' && $request->owner === 'php'
            ? new Response(503, ['Retry-After' => '120'])
            : $this->respond($request));

        self::assertSame('more', $scanner->tick(self::INVENTORY, 'foreman')['status']);
        $this->now = (int) $this->latest()['retry_at'];
        self::assertSame('failed', $scanner->tick(self::INVENTORY, 'foreman')['status']);
        $run = $this->latest();
        self::assertSame('failed', $run['status']);
        self::assertGreaterThan($this->now, (int) $run['retry_at']);
        self::assertSame(1, json_decode($run['counts'], true)['complete']);
    }

    public function testVaultRefusalForEveryOwnerFailsWithoutAnUnauthenticatedListing(): void
    {
        $vault = $this->container['vaultSecrets'];
        $vault->refusal = 'not_shared';
        $this->pdo->exec("INSERT INTO gumshoe_owners (login, kind) VALUES ('php', 'org')");
        $scanner = $this->scanner();
        self::assertSame('failed', $scanner->tick(self::INVENTORY, 'foreman')['status']);
        self::assertSame('failed', $this->latest()['status']);
        self::assertSame([], $this->requests);
        self::assertCount(1, $vault->reads);
        self::assertSame(['refused', 'missing'], $this->pdo->query(
            'SELECT token_status FROM gumshoe_owners ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));
    }

    public function testInaccessibleAndOutOfWatchRepositoriesArePreservedAndOldLogsPurged(): void
    {
        self::assertSame('done', $this->scanner()->tick(self::INVENTORY, 'cli')['status']);
        $this->pdo->exec("UPDATE gumshoe_runs SET started_at = 1, finished_at = 1");
        $this->pdo->exec("UPDATE gumshoe_dep_changes SET created_at = 1");
        $scanner = $this->scanner(fn (Request $request): Response => $request->operation === 'gh.branch'
            ? new Response(404) : $this->respond($request));
        self::assertSame('done', $scanner->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame('inaccessible', $this->pdo->query('SELECT outcome FROM gumshoe_repos')->fetchColumn());
        self::assertSame('unknown', $this->repoState());
        self::assertSame('open', $this->findingStatus());
        self::assertSame(1, json_decode($this->latest()['counts'], true)['inaccessible']);
        self::assertCount(1, (new RunLog($this->pdo))->recent());
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM gumshoe_dep_changes')->fetchColumn());

        $this->pdo->exec("UPDATE gumshoe_repos SET mode = 'exclude'");
        self::assertSame('done', $scanner->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame('out_of_watch', $this->pdo->query('SELECT outcome FROM gumshoe_repos')->fetchColumn());
        self::assertSame('open', $this->findingStatus());
    }

    private function latest(): array
    {
        return (new RunLog($this->pdo))->recent()[0];
    }

    private function repoState(): string
    {
        return $this->pdo->query('SELECT state FROM gumshoe_finding_repos')->fetchColumn();
    }

    private function findingStatus(): string
    {
        return $this->pdo->query('SELECT status FROM gumshoe_findings')->fetchColumn();
    }

    private function osvRequestBody(): string
    {
        foreach ($this->requests as $request) {
            if ($request->operation === 'osv.querybatch') {
                return $request->body;
            }
        }
        self::fail('No OSV query recorded.');
    }

    private function scanner(?\Closure $responder = null, ?\Closure $clock = null, ?\Closure $sleeper = null): Scanner
    {
        $send = function (Request $request) use ($responder): Response {
            self::assertFalse($this->pdo->inTransaction(), 'Outbound '.$request->operation.' opened inside a transaction.');
            $this->requests[] = $request;
            $this->phases[] = $this->latest()['phase'];
            return ($responder ?? $this->respond(...))($request);
        };
        $transport = new class($send) implements Transport {
            public function __construct(private readonly \Closure $send) {}
            public function send(#[\SensitiveParameter] Request $request, #[\SensitiveParameter] array $headers): Response
            {
                return ($this->send)($request);
            }
        };
        return new Scanner($this->container, $transport, 'https://kanboard.example', $clock ?? fn (): int => $this->now,
            $sleeper ?? static fn (int $seconds): null => null);
    }

    private function listing(): Response
    {
        return self::json([[
            'id' => 1, 'name' => 'yaml', 'owner' => ['login' => 'symfony', 'id' => 17],
            'private' => false, 'fork' => false, 'archived' => false,
            'pushed_at' => gmdate('Y-m-d\TH:i:s\Z', $this->now), 'default_branch' => 'main',
        ]]);
    }

    private function respond(Request $request): Response
    {
        return match ($request->operation) {
            'gh.list' => $this->listing(),
            'gh.branch' => self::json(['commit' => ['sha' => sha1('head-'.$this->version), 'commit' => ['tree' => ['sha' => sha1('tree-'.$this->version)]]]]),
            'gh.tree' => self::json(['truncated' => false, 'tree' => [[
                'path' => 'package-lock.json', 'type' => 'blob', 'mode' => '100644',
                'sha' => sha1($this->version), 'size' => 1024,
            ]]]),
            'gh.blob' => self::json(['lockfileVersion' => 3, 'packages' => [
                'node_modules/flatmap-stream' => [
                    'version' => $this->version, 'resolved' => 'https://registry.npmjs.org/flatmap-stream/-/flatmap-stream-'.$this->version.'.tgz',
                ],
            ]]),
            'osv.querybatch' => self::json(['results' => $this->vulnerable ? [
                ['vulns' => [['id' => self::ADVISORY, 'modified' => '2021-09-15T20:08:26Z']]],
            ] : [(object) []]]),
            'osv.vulns' => new Response(200, [], file_get_contents(__DIR__.'/fixtures/osv/vulns/'.self::ADVISORY.'.json')),
            'gh.advisories' => new Response(200, [], '[]'),
            'kev' => self::json(['vulnerabilities' => [['cveID' => 'CVE-2018-16492']]]),
            default => throw new RuntimeException('Unexpected test request'),
        };
    }

    private static function json(array $body): Response
    {
        return new Response(200, [], json_encode($body, JSON_THROW_ON_ERROR));
    }
}
