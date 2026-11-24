<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Advisory\AdvisoryCache;
use Kanboard\Plugin\Gumshoe\Advisory\Osv;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use PDO;
use KanboardTests\units\Base;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once __DIR__.'/bootstrap.php';
require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';

final class OsvTest extends Base
{
    use ReleasesConnection;

    private const API = 'https://api.osv.dev/v1/';
    private const SHA = '11bd71901bbe5b1630ceea73d27597364c9af683';
    private const FIRST = 'GHSA-29mw-wpgm-hmr9';
    private const SECOND = 'GHSA-35jh-r3h4-6jhm';
    private const THIRD = 'GHSA-r5fr-rjxr-66jc';
    private const OLD = '2025-09-29T21:12:31.102523Z';
    private const NEW = '2026-09-29T21:12:31.102523Z';

    public function testExactPublicBodiesPositionalPagesAndCacheRefresh(): void
    {
        [$pdo, $cache] = $this->database();
        $this->add($pdo, 'npm', 'lodash', '4.17.20');
        $this->add($pdo, 'npm', 'express', '4.0.0', 'private');
        $this->add($pdo, 'composer', 'symfony/yaml', 'v4.0.0');
        $this->add($pdo, 'actions', 'actions/checkout', self::SHA, type: 'commit');

        $cache->put('osv', self::FIRST, ['id' => self::FIRST, 'modified' => self::OLD], self::OLD, 900);
        $cache->put('osv', self::SECOND, ['id' => self::SECOND, 'modified' => self::OLD], self::OLD, 900);
        $transport = new FakeTransport([
            self::json(['results' => [
                ['vulns' => [self::vuln(self::FIRST, self::OLD)], 'next_page_token' => 'P:page-two:'],
                ['vulns' => [self::vuln(self::SECOND, self::NEW)]],
                (object) [],
            ]]),
            self::json(['results' => [['vulns' => [self::vuln(self::THIRD, self::NEW)]]]]),
            self::json(self::vuln(self::THIRD, self::NEW)),
            self::json(self::vuln(self::SECOND, self::NEW)),
        ]);

        $this->drain($this->osv($pdo, $transport));
        self::assertSame([
            '{"queries":[{"package":{"ecosystem":"npm","name":"lodash"},"version":"4.17.20"},{"package":{"ecosystem":"Packagist","name":"symfony/yaml"},"version":"v4.0.0"},{"commit":"'.self::SHA.'"}]}',
            '{"queries":[{"package":{"ecosystem":"npm","name":"lodash"},"version":"4.17.20","page_token":"P:page-two:"}]}',
            null,
            null,
        ], array_column($transport->requests, 'body'));
        self::assertSame([
            self::API.'querybatch', self::API.'querybatch',
            self::API.'vulns/'.self::THIRD, self::API.'vulns/'.self::SECOND,
        ], array_column($transport->requests, 'url'));
        self::assertSame([false, false, false, false], $transport->authenticated);
        self::assertSame([
            1 => [self::FIRST, self::THIRD], 3 => [self::SECOND], 4 => [],
        ], array_map(static fn (array $rows): array => array_column($rows, 'id'), $this->osv($pdo, new FakeTransport())->results(7)));
        self::assertSame(self::NEW, $cache->get('osv', self::SECOND)['modified']);
    }

    public function testBatchesHaveFixedMaximumSize(): void
    {
        [$pdo] = $this->database();
        $queries = [];
        for ($i = 0; $i < 2500; $i++) {
            $version = '4.17.20-build.'.$i;
            $this->add($pdo, 'npm', 'lodash', $version);
            $queries[] = ['package' => ['ecosystem' => 'npm', 'name' => 'lodash'], 'version' => $version];
        }
        $transport = new FakeTransport(array_map(static fn (int $size): Response =>
            self::json(['results' => array_fill(0, $size, (object) [])]), [1000, 1000, 500]));
        $this->drain($this->osv($pdo, $transport));
        self::assertSame(array_map(static fn (array $batch): string =>
            json_encode(['queries' => $batch], JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), array_chunk($queries, 1000)),
            array_column($transport->requests, 'body'));
        self::assertSame(2500, count($this->osv($pdo, new FakeTransport())->results(7)));
    }

    public function testFailurePersistsRetryAndDoesNotRecordCleanResults(): void
    {
        [$pdo] = $this->database();
        $this->add($pdo, 'npm', 'lodash', '4.17.20');
        $this->add($pdo, 'composer', 'symfony/yaml', 'v4.0.0');
        $transport = new FakeTransport([
            new Response(429, ['Retry-After' => '180']),
            self::json(['results' => [(object) [], (object) []]]),
        ]);
        $osv = $this->osv($pdo, $transport);
        self::assertSame(1180, $this->drain($osv));
        self::assertSame(['pending', 'pending'], $pdo->query('SELECT state FROM gumshoe_pending ORDER BY id')->fetchAll(PDO::FETCH_COLUMN));
        self::assertSame([1180, 1180], array_map(intval(...), $pdo->query('SELECT retry_at FROM gumshoe_pending ORDER BY id')->fetchAll(PDO::FETCH_COLUMN)));
        self::assertSame([], $osv->results(7));
        self::assertSame(1180, $this->drain($osv));
        self::assertCount(1, $transport->requests);
        self::assertNull($this->drain($this->osv($pdo, $transport, 1180)));
        self::assertSame([1 => [], 2 => []], $osv->results(7));
    }

    /** @dataProvider incompleteResponses */
    public function testMalformedOrInterruptedPagesRemainPending(array $responses): void
    {
        [$pdo] = $this->database();
        $this->add($pdo, 'npm', 'lodash', '4.17.20');
        $this->add($pdo, 'composer', 'symfony/yaml', 'v4.0.0');
        $osv = $this->osv($pdo, new FakeTransport($responses));
        self::assertSame(1060, $this->drain($osv));
        self::assertSame([], $osv->results(7));
    }

    public static function incompleteResponses(): iterable
    {
        yield 'wrong result count' => [[self::json(['results' => [['vulns' => []]]])]];
        yield 'invalid result' => [[new Response(200, [], '{"results":[{},[]]}')]];
        yield 'continuation fails' => [[
            self::json(['results' => [['next_page_token' => 'P:one:'], (object) []]]), new Response(503),
        ]];
        yield 'record fetch fails' => [[
            self::json(['results' => [['vulns' => [self::vuln(self::FIRST, self::NEW)]], (object) []]]), new Response(503),
        ]];
    }

    private function drain(Osv $osv): ?int
    {
        while (($rows = $osv->dueRows(7)) !== []) {
            $batch = $osv->fetch($rows, $osv->cachedVersions());
            $osv->store($batch);
        }
        return $osv->pendingRetryAt(7);
    }

    private function database(): array
    {
        $pdo = $this->container['db']->getConnection();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        version_1($pdo);
        return [$pdo, new AdvisoryCache($pdo)];
    }

    private function add(PDO $pdo, string $ecosystem, string $name, string $version, string $egress = 'public', string $type = 'package'): void
    {
        $pdo->prepare('INSERT INTO gumshoe_pending (run_id, query_type, ecosystem, name, version, egress) VALUES (7, ?, ?, ?, ?, ?)')
            ->execute([$type, $ecosystem, $name, $version, $egress]);
    }

    private function osv(PDO $pdo, FakeTransport $transport, int $now = 1000): Osv
    {
        $clock = static fn (): int => $now;
        return new Osv(new Client($transport, 'https://kanboard.example', clock: $clock), $pdo, clock: $clock);
    }

    private static function vuln(string $id, string $modified): array
    {
        return ['id' => $id, 'modified' => $modified];
    }

    private static function json(array $body): Response
    {
        return new Response(200, [], json_encode($body, JSON_THROW_ON_ERROR));
    }
}
