<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Http\Transport;
use Kanboard\Plugin\Gumshoe\Run\Jobs;
use Kanboard\Plugin\Gumshoe\Run\RunLog;
use Kanboard\Plugin\Gumshoe\Run\Scanner;
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
        $this->requests = [];
        self::assertSame('done', $jobs[1]['run']($this->now + 10)['status']);
        self::assertSame(['osv.querybatch'], array_column($this->requests, 'operation'));
        self::assertStringContainsString('"version":"0.1.1"', $this->osvRequestBody());
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
        self::assertSame('done', $scanner->tick(self::INVENTORY, 'foreman')['status']);
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

    public function testVaultRefusalDoesNotMakeAnUnauthenticatedListing(): void
    {
        $this->container['vaultSecrets']->ready = false;
        $scanner = $this->scanner();
        self::assertSame('more', $scanner->tick(self::INVENTORY, 'cli')['status']);
        $this->now = (int) $this->latest()['retry_at'];
        self::assertSame('failed', $scanner->tick(self::INVENTORY, 'cli')['status']);
        self::assertSame([], $this->requests);
        self::assertSame('refused', $this->pdo->query('SELECT token_status FROM gumshoe_owners')->fetchColumn());
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

    private function scanner(?\Closure $responder = null, ?\Closure $clock = null): Scanner
    {
        $send = function (Request $request) use ($responder): Response {
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
        return new Scanner($this->container, $transport, 'https://kanboard.example', $clock ?? fn (): int => $this->now);
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
            'gh.branch' => self::json(['commit' => ['sha' => self::SHA, 'commit' => ['tree' => ['sha' => self::SHA]]]]),
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
