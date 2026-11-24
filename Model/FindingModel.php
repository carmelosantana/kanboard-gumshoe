<?php

namespace Kanboard\Plugin\Gumshoe\Model;

use Kanboard\Plugin\Gumshoe\Inventory\Dependency;
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

    public function hasLockfiles(int $repoId): bool
    {
        return $this->execute('SELECT 1 FROM gumshoe_lockfiles WHERE repo_id = ? LIMIT 1', [$repoId])->fetchColumn() !== false;
    }

    /** Consolidate persisted group merges, including merges discovered before this run. */
    public function mergeAbsorbedFindings(): array
    {
        $absorbed = $this->execute(
            "SELECT f.id, f.group_id, f.ecosystem, f.package, f.status, g.merged_into
             FROM gumshoe_findings f JOIN gumshoe_groups g ON g.id = f.group_id
             WHERE g.merged_into IS NOT NULL AND f.status <> 'merged' ORDER BY f.id",
            [],
        )->fetchAll(PDO::FETCH_ASSOC);

        $statusRank = ['fixed' => 0, 'dismissed' => 1, 'open' => 2];
        $transitions = [];
        foreach ($absorbed as $finding) {
            $id = (int) $finding['id'];
            $groupId = $this->survivingGroup((int) $finding['group_id'], (int) $finding['merged_into']);
            $survivor = $this->findOrCreate($groupId, $finding['ecosystem'], $finding['package'], $finding['status']);
            $survivorId = (int) $survivor['id'];
            if ($statusRank[$finding['status']] > $statusRank[$survivor['status']]) {
                $this->execute('UPDATE gumshoe_findings SET status = ? WHERE id = ?', [$finding['status'], $survivorId]);
            }

            $this->moveExposures($id, $survivorId);
            $this->moveRepos($id, $survivorId);
            $this->execute("UPDATE gumshoe_findings SET status = 'merged' WHERE id = ?", [$id]);
            $transitions[$id] = ['from' => $finding['status'], 'to' => 'merged', 'survivor_finding_id' => $survivorId];
        }

        return $transitions;
    }

    private function survivingGroup(int $groupId, int $target): int
    {
        $visited = [$groupId => true];
        while (!isset($visited[$target])) {
            $visited[$target] = true;
            $next = $this->execute('SELECT merged_into FROM gumshoe_groups WHERE id = ?', [$target])->fetchColumn();
            if ($next === null) {
                return $target;
            }
            if ($next === false) {
                break;
            }
            $target = (int) $next;
        }

        throw new RuntimeException('Invalid advisory group merge chain.');
    }

    private function moveExposures(int $absorbedId, int $survivorId): void
    {
        $rows = $this->execute('SELECT * FROM gumshoe_exposures WHERE finding_id = ?', [$absorbedId])->fetchAll(PDO::FETCH_ASSOC);
        $where = 'finding_id = ? AND repo_id = ? AND lockfile_id = ? AND version = ?';
        foreach ($rows as $row) {
            $identity = [$row['repo_id'], $row['lockfile_id'], $row['version']];
            $existing = $this->execute('SELECT active, first_seen, last_seen FROM gumshoe_exposures WHERE '.$where, [$survivorId, ...$identity])
                ->fetch(PDO::FETCH_ASSOC);
            if ($existing === false) {
                $this->execute('UPDATE gumshoe_exposures SET finding_id = ? WHERE '.$where, [$survivorId, $absorbedId, ...$identity]);
                continue;
            }

            $this->execute(
                'UPDATE gumshoe_exposures SET active = ?, first_seen = ?, last_seen = ? WHERE '.$where,
                [
                    (int) ($row['active'] || $existing['active']),
                    min($row['first_seen'], $existing['first_seen']),
                    max($row['last_seen'], $existing['last_seen']),
                    $survivorId, ...$identity,
                ],
            );
            $this->execute('DELETE FROM gumshoe_exposures WHERE '.$where, [$absorbedId, ...$identity]);
        }
    }

    private function moveRepos(int $absorbedId, int $survivorId): void
    {
        $stateRank = ['fixed' => 0, 'unknown' => 1, 'affected' => 2];
        $rows = $this->execute('SELECT * FROM gumshoe_finding_repos WHERE finding_id = ?', [$absorbedId])->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as $row) {
            $repoId = (int) $row['repo_id'];
            $existing = $this->execute(
                'SELECT state, ever_affected FROM gumshoe_finding_repos WHERE finding_id = ? AND repo_id = ?',
                [$survivorId, $repoId],
            )->fetch(PDO::FETCH_ASSOC);
            $state = $row['state'];
            if ($existing !== false && $stateRank[$existing['state']] > $stateRank[$state]) {
                $state = $existing['state'];
            }

            // A subtask ID belongs to the original task. Keep only the survivor's ID.
            $this->writeRepoState($survivorId, $repoId, $state, $row['ever_affected'] || !empty($existing['ever_affected']), $existing !== false);
        }
        $this->execute('DELETE FROM gumshoe_finding_repos WHERE finding_id = ?', [$absorbedId]);
    }

    private function findOrCreate(int $groupId, string $ecosystem, string $package, string $status = 'open'): array
    {
        $identity = [$groupId, $ecosystem, $package];
        $select = 'SELECT id, status FROM gumshoe_findings WHERE group_id = ? AND ecosystem = ? AND package = ?';
        $row = $this->execute($select, $identity)->fetch(PDO::FETCH_ASSOC);
        if ($row === false) {
            $this->execute('INSERT INTO gumshoe_findings (group_id, ecosystem, package, status) VALUES (?, ?, ?, ?)', [...$identity, $status]);
            $row = $this->execute($select, $identity)->fetch(PDO::FETCH_ASSOC);
        }

        return $row;
    }

    public function recordExposure(array $match, int $now): int
    {
        $findingId = (int) $this->findOrCreate($match['group_id'], $match['ecosystem'], $match['package'])['id'];
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

        return $findingId;
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
        $queryType = $exposure['ecosystem'] === 'actions' ? Dependency::QUERY_COMMIT : Dependency::QUERY_PACKAGE;
        $unfinished = $this->execute(
            "SELECT 1 FROM gumshoe_pending
             WHERE run_id = ? AND query_type = ? AND ecosystem = ? AND name = ? AND version = ?
               AND egress = 'public' AND (state <> 'done' OR retry_at IS NOT NULL OR page_token IS NOT NULL) LIMIT 1",
            [$runId, $queryType, $exposure['ecosystem'], $exposure['package'], $exposure['version']],
        )->fetchColumn();
        if ($unfinished !== false) {
            return false;
        }

        // Current public versions of this package need answers too.
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

    public function hasInstalledVersion(int $repoId, array $exposure): bool
    {
        return $this->execute(
            'SELECT 1 FROM gumshoe_lockfiles l JOIN gumshoe_deps d ON d.lockfile_id = l.id
             WHERE l.repo_id = ? AND l.id = ? AND d.ecosystem = ? AND d.name = ? AND d.version = ?
             LIMIT 1',
            [$repoId, $exposure['lockfile_id'], $exposure['ecosystem'], $exposure['package'], $exposure['version']],
        )->fetchColumn() !== false;
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
        $this->writeRepoState($findingId, $repoId, $state, $state === 'affected' || !empty($previous['ever_affected']), $previous !== null);
    }

    private function writeRepoState(int $findingId, int $repoId, string $state, bool $everAffected, bool $exists): void
    {
        $values = [$state, (int) $everAffected, $findingId, $repoId];
        if (!$exists) {
            $this->execute(
                'INSERT INTO gumshoe_finding_repos (state, ever_affected, finding_id, repo_id) VALUES (?, ?, ?, ?)',
                $values,
            );
        } else {
            $this->execute(
                'UPDATE gumshoe_finding_repos SET state = ?, ever_affected = ? WHERE finding_id = ? AND repo_id = ?',
                $values,
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
