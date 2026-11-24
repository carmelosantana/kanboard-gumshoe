<?php

namespace Kanboard\Plugin\Gumshoe\Advisory;

use DateTimeImmutable;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Inventory\Dependency;
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

    /** Process due public rows. Returns the next retry time, or null when no public rows remain pending. */
    public function queryPending(int $runId): ?int
    {
        $now = ($this->clock)();
        $pending = $this->pdo->prepare(
            "SELECT id, query_type, ecosystem, name, version FROM gumshoe_pending
             WHERE run_id = ? AND egress = 'public' AND state = 'pending' AND (retry_at IS NULL OR retry_at <= ?)
             ORDER BY id LIMIT ".self::BATCH_SIZE
        );
        while (true) {
            $pending->execute([$runId, $now]);
            $rows = $pending->fetchAll(PDO::FETCH_ASSOC);
            if ($rows === []) {
                break;
            }
            if (($retryAt = $this->process($rows)) !== null) {
                return $retryAt;
            }
        }
        $next = $this->pdo->prepare(
            "SELECT MIN(retry_at) FROM gumshoe_pending WHERE run_id = ? AND egress = 'public' AND state = 'pending'"
        );
        $next->execute([$runId]);
        $retryAt = $next->fetchColumn();
        return $retryAt === null ? null : (int) $retryAt;
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

    private function process(array $rows): ?int
    {
        $retryAt = null;
        try {
            $queries = array_map($this->query(...), $rows);
            $pages = $this->batch($queries, $retryAt);
            $matches = [];
            foreach ($rows as $index => $row) {
                $matches[$row['id']] = $this->collect($queries[$index], $pages[$index], $retryAt);
            }
        } catch (HttpFailure) {
            $retryAt = max(($this->clock)() + 1, $retryAt ?? ($this->clock)() + 60);
            $this->pdo->beginTransaction();
            try {
                $retry = $this->pdo->prepare("UPDATE gumshoe_pending SET retry_at = ? WHERE id = ? AND state = 'pending'");
                foreach ($rows as $row) {
                    $retry->execute([$retryAt, $row['id']]);
                }
                $this->pdo->commit();
            } catch (\Throwable $failure) {
                $this->pdo->rollBack();
                throw $failure;
            }
            return $retryAt;
        }

        // Keep the association with the pending row across scanner slices and restarts.
        $this->pdo->beginTransaction();
        try {
            $done = $this->pdo->prepare("UPDATE gumshoe_pending SET state = 'done', page_token = NULL, retry_at = NULL WHERE id = ? AND state = 'pending'");
            foreach ($matches as $id => $ids) {
                $done->execute([$id]);
                $this->cache->put(self::RESULTS, (string) $id, $ids, null, ($this->clock)());
            }
            $this->pdo->commit();
        } catch (\Throwable $failure) {
            $this->pdo->rollBack();
            throw $failure;
        }
        return null;
    }

    private function query(array $row): array
    {
        if ($row['query_type'] === Dependency::QUERY_COMMIT && $row['ecosystem'] === 'actions'
            && preg_match('/\A[0-9a-f]{40}\z/i', $row['version']) === 1) {
            return ['commit' => $row['version']];
        }
        if ($row['query_type'] === Dependency::QUERY_PACKAGE && in_array($row['ecosystem'], ['npm', 'composer'], true)) {
            return [
                'package' => [
                    'ecosystem' => $row['ecosystem'] === 'composer' ? 'Packagist' : 'npm',
                    'name' => $row['name'],
                ],
                'version' => $row['version'],
            ];
        }
        throw new HttpFailure('osv.querybatch', self::HOST, null, 'invalid_query');
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

    private function collect(array $query, mixed $page, ?int &$retryAt): array
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
                $this->fetchAdvisory($id, $modified, $retryAt);
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

    private function fetchAdvisory(string $id, string $modified, ?int &$retryAt): void
    {
        $cached = $this->cache->get('osv', $id);
        $expected = self::timestamp($modified);
        if ($cached !== null && self::timestamp($cached['modified']) >= $expected) {
            return;
        }
        $record = $this->send(new Request('osv.vulns', self::API.'vulns/'.rawurlencode($id)), $retryAt);
        $updated = self::timestamp($record->modified ?? null);
        if (($record->id ?? null) !== $id || $updated === null || $updated < $expected) {
            throw new HttpFailure('osv.vulns', self::HOST, 200, 'invalid_response');
        }
        $this->cache->put('osv', $id, (array) $record, $record->modified, ($this->clock)());
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
