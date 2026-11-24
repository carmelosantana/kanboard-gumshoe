<?php

namespace Kanboard\Plugin\Gumshoe\Model;

use PDO;
use PDOStatement;
use RuntimeException;
use Throwable;

final class FindingModel
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /** Join a caller's transaction when reconciliation is part of a fenced batch. */
    public function transaction(callable $write): array
    {
        if ($this->pdo->inTransaction()) {
            return $write();
        }

        $this->pdo->beginTransaction();
        try {
            $result = $write();
            $this->pdo->commit();
            return $result;
        } catch (Throwable $error) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }

    public function context(int $runId, int $repoId): array
    {
        $row = $this->execute(
            'SELECT runs.job, r.name AS repo, r.outcome, o.login AS owner, o.enabled
             FROM gumshoe_repos r JOIN gumshoe_owners o ON o.id = r.owner_id
             CROSS JOIN gumshoe_runs runs WHERE r.id = ? AND runs.id = ?',
            [$repoId, $runId],
        )->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            throw new RuntimeException('Reconciliation requires an existing run and repository.');
        }

        return $row;
    }

    public function hasIncompleteLockfiles(int $repoId): bool
    {
        return $this->execute(
            "SELECT 1 FROM gumshoe_lockfiles WHERE repo_id = ? AND status <> 'ok' LIMIT 1",
            [$repoId],
        )->fetchColumn() !== false;
    }

    public function recordExposure(array $match, int $now): int
    {
        $identity = [$match['group_id'], $match['ecosystem'], $match['package']];
        $select = 'SELECT id FROM gumshoe_findings WHERE group_id = ? AND ecosystem = ? AND package = ?';
        $findingId = $this->execute($select, $identity)->fetchColumn();
        if ($findingId === false) {
            $this->execute('INSERT INTO gumshoe_findings (group_id, ecosystem, package) VALUES (?, ?, ?)', $identity);
            $findingId = $this->execute($select, $identity)->fetchColumn();
        }

        $key = [$findingId, $match['repo_id'], $match['lockfile_id'], $match['version']];
        $where = 'finding_id = ? AND repo_id = ? AND lockfile_id = ? AND version = ?';
        if ($this->execute('SELECT 1 FROM gumshoe_exposures WHERE '.$where, $key)->fetchColumn() === false) {
            $this->execute(
                'INSERT INTO gumshoe_exposures (finding_id, repo_id, lockfile_id, version, first_seen, last_seen)
                 VALUES (?, ?, ?, ?, ?, ?)',
                [...$key, $now, $now],
            );
        } else {
            $this->execute('UPDATE gumshoe_exposures SET active = 1, last_seen = ? WHERE '.$where, [$now, ...$key]);
        }

        return (int) $findingId;
    }

    public function forRepo(int $repoId): array
    {
        $rows = $this->execute(
            "SELECT r.* FROM gumshoe_finding_repos r JOIN gumshoe_findings f ON f.id = r.finding_id
             WHERE r.repo_id = ? AND f.status <> 'merged' ORDER BY r.finding_id",
            [$repoId],
        )->fetchAll(PDO::FETCH_ASSOC);

        return array_column($rows, null, 'finding_id');
    }

    public function activeExposures(int $repoId): array
    {
        return $this->execute(
            "SELECT e.finding_id, e.lockfile_id, e.version, f.ecosystem, f.package
             FROM gumshoe_exposures e JOIN gumshoe_findings f ON f.id = e.finding_id
             WHERE e.repo_id = ? AND e.active = 1 AND f.status <> 'merged' ORDER BY e.finding_id",
            [$repoId],
        )->fetchAll(PDO::FETCH_ASSOC);
    }

    public function hasCompleteAnswers(int $runId, int $repoId, array $exposure): bool
    {
        // An unfinished query for the previously exposed version can still change the match set.
        $unfinished = $this->execute(
            "SELECT 1 FROM gumshoe_pending
             WHERE run_id = ? AND ecosystem = ? AND name = ? AND version = ?
               AND egress = 'public' AND state <> 'done' LIMIT 1",
            [$runId, $exposure['ecosystem'], $exposure['package'], $exposure['version']],
        )->fetchColumn();
        if ($unfinished !== false) {
            return false;
        }

        // Current public versions of this package need answers too. A retained exposed version
        // that lost public evidence is a coverage gap, so absence from Matcher proves nothing.
        return $this->execute(
            "SELECT 1 FROM gumshoe_lockfiles l JOIN gumshoe_deps d ON d.lockfile_id = l.id
             LEFT JOIN gumshoe_pending p ON p.run_id = ? AND p.query_type = d.query_type
               AND p.ecosystem = d.ecosystem AND p.name = d.name AND p.version = d.version
               AND p.egress = 'public' AND p.state = 'done' AND p.retry_at IS NULL AND p.page_token IS NULL
             WHERE l.repo_id = ? AND d.ecosystem = ? AND d.name = ?
               AND ((d.egress = 'public' AND p.id IS NULL) OR (d.egress <> 'public' AND d.version = ?))
             LIMIT 1",
            [$runId, $repoId, $exposure['ecosystem'], $exposure['package'], $exposure['version']],
        )->fetchColumn() === false;
    }

    public function retireExposure(int $repoId, array $exposure): void
    {
        $this->execute(
            'UPDATE gumshoe_exposures SET active = 0
             WHERE finding_id = ? AND repo_id = ? AND lockfile_id = ? AND version = ?',
            [$exposure['finding_id'], $repoId, $exposure['lockfile_id'], $exposure['version']],
        );
    }

    public function setRepoState(int $findingId, int $repoId, string $state, ?array $previous): void
    {
        $everAffected = (int) ($state === 'affected' || !empty($previous['ever_affected']));
        if ($previous === null) {
            $this->execute(
                'INSERT INTO gumshoe_finding_repos (state, ever_affected, finding_id, repo_id) VALUES (?, ?, ?, ?)',
                [$state, $everAffected, $findingId, $repoId],
            );
        } else {
            $this->execute(
                'UPDATE gumshoe_finding_repos SET state = ?, ever_affected = ? WHERE finding_id = ? AND repo_id = ?',
                [$state, $everAffected, $findingId, $repoId],
            );
        }
    }

    private function execute(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($parameters);
        return $statement;
    }
}
