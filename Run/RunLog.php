<?php

namespace Kanboard\Plugin\Gumshoe\Run;

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
        $this->execute(
            'UPDATE gumshoe_runs SET status = ?, finished_at = ?, exception_class = ?, retry_at = ? WHERE id = ?',
            [$status, $now, $error, $retryAt, $id],
        );
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
