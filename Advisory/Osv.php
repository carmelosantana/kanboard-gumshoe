<?php

namespace Kanboard\Plugin\Gumshoe\Advisory;

use DateTimeImmutable;
use Kanboard\Plugin\Gumshoe\Egress\Policy;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use PDO;
use stdClass;

final class Osv
{
    private const HOST = 'api.osv.dev';
    private const API = 'https://'.self::HOST.'/v1/';
    private const BATCH_SIZE = 1000;
    private const RESULTS = 'osv-query';

    private readonly AdvisoryCache $cache;
    private readonly \Closure $clock;

    public function __construct(private readonly Client $client, private readonly PDO $pdo, ?\Closure $clock = null)
    {
        $this->cache = new AdvisoryCache($pdo);
        $this->clock = $clock ?? time(...);
    }

    public function dueRows(int $runId): array
    {
        $pending = $this->pdo->prepare(
            "SELECT id, query_type, ecosystem, name, version, egress FROM gumshoe_pending
             WHERE run_id = ? AND egress = 'public' AND state = 'pending' AND (retry_at IS NULL OR retry_at <= ?)
             ORDER BY id LIMIT ".self::BATCH_SIZE
        );
        $pending->execute([$runId, ($this->clock)()]);
        return $pending->fetchAll(PDO::FETCH_ASSOC);
    }

    public function pendingRetryAt(int $runId): ?int
    {
        $next = $this->pdo->prepare(
            "SELECT MIN(retry_at) FROM gumshoe_pending WHERE run_id = ? AND egress = 'public' AND state = 'pending'"
        );
        $next->execute([$runId]);
        $retryAt = $next->fetchColumn();
        return $retryAt === null ? null : (int) $retryAt;
    }

    public function cachedVersions(): array
    {
        return $this->pdo->query("SELECT advisory_id, modified FROM gumshoe_advisory_cache WHERE source = 'osv'")
            ->fetchAll(PDO::FETCH_KEY_PAIR);
    }

    /** @return array<int, list<array>> Completed results keyed by pending row ID. An empty list is a completed clean query. */
    public function results(int $runId): array
    {
        $statement = $this->pdo->prepare(
            "SELECT p.id, c.body FROM gumshoe_pending p
             JOIN gumshoe_advisory_cache c ON c.source = ? AND c.advisory_id = CAST(p.id AS ".$this->idCast().")
             WHERE p.run_id = ? AND p.egress = 'public' AND p.state = 'done' ORDER BY p.id"
        );
        $statement->execute([self::RESULTS, $runId]);
        $matches = [];
        $advisories = [];
        foreach ($statement->fetchAll(PDO::FETCH_ASSOC) as $row) {
            $ids = json_decode($row['body'], true, flags: JSON_THROW_ON_ERROR);
            $records = [];
            foreach ($ids as $id) {
                $records[] = $advisories[$id] ??= $this->cache->get('osv', $id)['body']
                    ?? throw new \RuntimeException('Missing OSV advisory for a completed query');
            }
            $matches[(int) $row['id']] = $records;
        }
        return $matches;
    }

    private function idCast(): string
    {
        return $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? 'CHAR' : 'TEXT';
    }

    /** Fetch a single batch and its advisory details without touching the database. */
    public function fetch(array $rows, array $cached): array
    {
        $ids = [];
        $rejected = [];
        $queries = [];
        foreach ($rows as $row) {
            if (!Policy::allowsPendingQuery($row)) {
                $rejected[] = $row['id'];
                continue;
            }
            $ids[] = $row['id'];
            $queries[] = $this->query($row);
        }

        $retryAt = null;
        $records = [];
        $matches = [];
        try {
            if ($queries !== []) {
                $pages = $this->batch($queries, $retryAt);
                foreach ($ids as $index => $id) {
                    $matches[$id] = $this->collect($queries[$index], $pages[$index], $retryAt, $cached, $records);
                }
            }
        } catch (HttpFailure) {
            $now = ($this->clock)();
            $retryAt = max($now + 1, $retryAt ?? $now + 60);
            $matches = [];
        }

        return ['ids' => $ids, 'rejected' => $rejected, 'matches' => $matches, 'records' => $records, 'retryAt' => $retryAt];
    }

    /** Publish the batch inside the caller's transaction. */
    public function store(array $batch): void
    {
        if ($batch['rejected'] !== []) {
            $reject = $this->pdo->prepare(
                "UPDATE gumshoe_pending SET egress = 'unqueryable', page_token = NULL, retry_at = NULL
                 WHERE id = ? AND state = 'pending' AND egress = 'public'"
            );
            foreach ($batch['rejected'] as $id) {
                $reject->execute([$id]);
            }
        }
        foreach ($batch['records'] as $id => $record) {
            $this->cache->put('osv', $id, $record, $record['modified'], ($this->clock)());
        }
        if ($batch['retryAt'] !== null) {
            $retry = $this->pdo->prepare("UPDATE gumshoe_pending SET retry_at = ? WHERE id = ? AND state = 'pending'");
            foreach ($batch['ids'] as $id) {
                $retry->execute([$batch['retryAt'], $id]);
            }
            return;
        }

        // Keep the association with the pending row across scanner slices and restarts.
        $done = $this->pdo->prepare("UPDATE gumshoe_pending SET state = 'done', page_token = NULL, retry_at = NULL WHERE id = ? AND state = 'pending'");
        foreach ($batch['matches'] as $id => $ids) {
            $done->execute([$id]);
            $this->cache->put(self::RESULTS, (string) $id, $ids, null, ($this->clock)());
        }
    }

    private function query(array $row): array
    {
        if ($row['ecosystem'] === 'actions') {
            return ['commit' => $row['version']];
        }
        return [
            'package' => [
                'ecosystem' => $row['ecosystem'] === 'composer' ? 'Packagist' : 'npm',
                'name' => $row['name'],
            ],
            'version' => $row['version'],
        ];
    }

    /** @return list<mixed> Result slots in request order. */
    private function batch(array $queries, ?int &$retryAt): array
    {
        $result = $this->send(new Request(
            'osv.querybatch',
            self::API.'querybatch',
            method: 'POST',
            body: json_encode(['queries' => $queries], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
            headers: ['Content-Type' => 'application/json'],
        ), $retryAt);
        if (!is_array($result->results ?? null) || count($result->results) !== count($queries)) {
            throw new HttpFailure('osv.querybatch', self::HOST, 200, 'invalid_response');
        }
        return $result->results;
    }

    private function collect(array $query, mixed $page, ?int &$retryAt, array $cached, array &$records): array
    {
        $ids = [];
        $seen = [];
        while (true) {
            if (!$page instanceof stdClass
                || array_diff(array_keys(get_object_vars($page)), ['vulns', 'next_page_token']) !== []
                || (property_exists($page, 'vulns') && !is_array($page->vulns))) {
                throw new HttpFailure('osv.querybatch', self::HOST, 200, 'invalid_response');
            }
            foreach ($page->vulns ?? [] as $vulnerability) {
                $id = $vulnerability->id ?? null;
                $modified = $vulnerability->modified ?? null;
                if (!is_string($id) || preg_match('/\A[A-Za-z0-9][A-Za-z0-9._-]{0,254}\z/', $id) !== 1
                    || self::timestamp($modified) === null) {
                    throw new HttpFailure('osv.querybatch', self::HOST, 200, 'invalid_response');
                }
                $this->fetchAdvisory($id, $modified, $retryAt, $cached, $records);
                $ids[$id] = $id;
            }
            if (!property_exists($page, 'next_page_token') || $page->next_page_token === '') {
                return array_values($ids);
            }
            $token = $page->next_page_token;
            if (!is_string($token) || isset($seen[$token])) {
                throw new HttpFailure('osv.querybatch', self::HOST, 200, 'invalid_pagination');
            }
            $seen[$token] = true;
            [$page] = $this->batch([$query + ['page_token' => $token]], $retryAt);
        }
    }

    private function fetchAdvisory(string $id, string $modified, ?int &$retryAt, array $cached, array &$records): void
    {
        $known = $records[$id]['modified'] ?? $cached[$id] ?? null;
        $expected = self::timestamp($modified);
        if ($known !== null && self::timestamp($known) >= $expected) {
            return;
        }
        $record = $this->send(new Request('osv.vulns', self::API.'vulns/'.rawurlencode($id)), $retryAt);
        $updated = self::timestamp($record->modified ?? null);
        if (($record->id ?? null) !== $id || $updated === null || $updated < $expected) {
            throw new HttpFailure('osv.vulns', self::HOST, 200, 'invalid_response');
        }
        $records[$id] = (array) $record;
    }

    private function send(Request $request, ?int &$retryAt): mixed
    {
        $response = $this->client->send($request);
        if ($response->status !== 200) {
            $retryAt = $response->retryAt;
            throw new HttpFailure($request->operation, self::HOST, $response->status, 'request_failed');
        }
        return json_decode($response->body);
    }

    private static function timestamp(mixed $value): ?DateTimeImmutable
    {
        if (!is_string($value) || preg_match('/\A\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d{1,9})?(?:Z|[+-]\d\d:\d\d)\z/', $value) !== 1) {
            return null;
        }
        try {
            return new DateTimeImmutable($value);
        } catch (\Exception) {
            return null;
        }
    }
}
