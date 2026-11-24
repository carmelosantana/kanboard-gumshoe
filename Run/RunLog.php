<?php

namespace Kanboard\Plugin\Gumshoe\Run;

use Kanboard\Plugin\Gumshoe\Advisory\AdvisoryCache;
use PDO;
use PDOStatement;

final readonly class RunLog
{
    public function __construct(private PDO $pdo)
    {
    }

    public function recent(int $limit = 50): array
    {
        $limit = max(1, min(50, $limit));
        return $this->rows('SELECT * FROM gumshoe_runs ORDER BY id DESC LIMIT '.$limit);
    }

    public function active(): ?array
    {
        return $this->rows("SELECT * FROM gumshoe_runs WHERE status = 'more' ORDER BY id LIMIT 1")[0] ?? null;
    }

    public function latest(string $job): ?array
    {
        return $this->rows('SELECT * FROM gumshoe_runs WHERE job = ? ORDER BY id DESC LIMIT 1', [$job])[0] ?? null;
    }

    public function start(string $job, string $trigger, string $phase, int $now): array
    {
        $column = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? '`trigger`' : '"trigger"';
        $this->execute("INSERT INTO gumshoe_runs (job, $column, phase, started_at) VALUES (?, ?, ?, ?)",
            [$job, $trigger, $phase, $now]);
        return $this->latest($job);
    }

    public function checkpoint(int $id, string $phase, ?int $position, ?int $retryAt = null, ?string $error = null): void
    {
        $this->execute(
            'UPDATE gumshoe_runs SET phase = ?, position = ?, retry_at = ?, exception_class = ? WHERE id = ?',
            [$phase, $position === null ? null : (string) $position, $retryAt, $error, $id],
        );
    }

    public function finish(int $id, string $status, int $now, ?string $error = null, ?int $retryAt = null): void
    {
        $this->retirePending($id);
        $this->execute(
            'UPDATE gumshoe_runs SET status = ?, finished_at = ?, exception_class = ?, retry_at = ? WHERE id = ?',
            [$status, $now, $error, $retryAt, $id],
        );
    }

    private function retirePending(int $id): void
    {
        // Osv associates answers with pending row IDs while matching a run.
        // Once that run is terminal, retain only the latest answer per identity.
        $cast = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? 'CHAR' : 'TEXT';
        $rows = $this->rows("SELECT p.query_type, p.ecosystem, p.name, p.version, c.body, c.fetched_at
            FROM gumshoe_pending p JOIN gumshoe_advisory_cache c ON c.source = 'osv-query'
                AND c.advisory_id = CAST(p.id AS $cast)
            WHERE p.run_id = ? AND p.state = 'done' AND p.egress = 'public'", [$id]);
        $cache = new AdvisoryCache($this->pdo);
        foreach ($rows as $row) {
            $key = 'query:'.hash('sha256', json_encode(
                [$row['query_type'], $row['ecosystem'], $row['name'], $row['version']],
                JSON_THROW_ON_ERROR,
            ));
            $fetchedAt = (int) $row['fetched_at'];
            if (($cache->get('osv-query', $key)['fetched_at'] ?? 0) <= $fetchedAt) {
                $cache->put('osv-query', $key, json_decode($row['body'], true, flags: JSON_THROW_ON_ERROR), null, $fetchedAt);
            }
        }
        $this->execute("DELETE FROM gumshoe_advisory_cache WHERE source = 'osv-query' AND advisory_id IN
            (SELECT CAST(id AS $cast) FROM gumshoe_pending WHERE run_id = ?)", [$id]);
        $this->execute('DELETE FROM gumshoe_pending WHERE run_id = ?', [$id]);
    }

    public function defer(int $id, int $retryAt): void
    {
        $this->execute('UPDATE gumshoe_runs SET retry_at = ? WHERE id = ?', [$retryAt, $id]);
    }

    public function counts(int $id): array
    {
        return json_decode($this->execute('SELECT counts FROM gumshoe_runs WHERE id = ?', [$id])->fetchColumn(),
            true, flags: JSON_THROW_ON_ERROR);
    }

    public function saveCounts(int $id, array $counts): void
    {
        $this->execute('UPDATE gumshoe_runs SET counts = ? WHERE id = ?', [json_encode($counts, JSON_THROW_ON_ERROR), $id]);
    }

    public function purge(int $now): void
    {
        $cutoff = $now - 180 * 86400;
        $oldRuns = "SELECT id FROM gumshoe_runs WHERE started_at < ? AND status <> 'more'";
        $cast = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql' ? 'CHAR' : 'TEXT';
        $this->execute("DELETE FROM gumshoe_advisory_cache WHERE source = 'osv-query' AND advisory_id IN
            (SELECT CAST(id AS $cast) FROM gumshoe_pending WHERE run_id IN ($oldRuns))", [$cutoff]);
        $this->execute("DELETE FROM gumshoe_pending WHERE run_id IN ($oldRuns)", [$cutoff]);
        $this->execute('DELETE FROM gumshoe_dep_changes WHERE created_at < ?', [$cutoff]);
        $this->execute("DELETE FROM gumshoe_runs WHERE started_at < ? AND status <> 'more'", [$cutoff]);
    }

    private function rows(string $sql, array $parameters = []): array
    {
        return $this->execute($sql, $parameters)->fetchAll(PDO::FETCH_ASSOC);
    }

    private function execute(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($parameters);
        return $statement;
    }
}
