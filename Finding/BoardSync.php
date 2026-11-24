<?php

namespace Kanboard\Plugin\Gumshoe\Finding;

use Kanboard\Core\Base;
use Kanboard\Model\SubtaskModel;
use Kanboard\Plugin\Gumshoe\Advisory\AdvisoryCache;
use Kanboard\Plugin\Gumshoe\Advisory\Priority;
use Kanboard\Plugin\Gumshoe\Model\FindingModel;
use PDO;
use PDOStatement;
use RuntimeException;
use Throwable;

final class BoardSync extends Base
{
    /**
     * Sync one persisted finding under the scanner's single writer lease.
     * Repo transitions from Reconciler, when available, are keyed by repo ID.
     * Returns project_unavailable when the configured or actual board is unsafe.
     */
    public function sync(int $findingId, int $targetProject, int $runId, array $repoTransitions = []): ?string
    {
        $finding = $this->sql(
            'SELECT f.*, g.primary_id, g.cvss_max, g.malware, g.kev, g.merged_into
             FROM gumshoe_findings f JOIN gumshoe_groups g ON g.id = f.group_id WHERE f.id = ?',
            [$findingId],
        )->fetch(PDO::FETCH_ASSOC);
        if ($finding === false) {
            throw new RuntimeException('Board sync requires an existing finding.');
        }

        if ($this->privateProject($targetProject) === []) {
            return $this->unavailable($runId);
        }
        if ($finding['status'] === 'merged') {
            return $this->syncMerged($finding, $targetProject, $runId);
        }

        $reference = 'gumshoe:finding:'.$findingId;
        $task = $this->findTask($finding);
        $previousProject = (int) $finding['project_id'];
        $snapshot = $this->snapshot($finding);
        $priority = Priority::of($finding);
        $repos = $this->repos($findingId);
        $affected = array_filter($repos, static fn (array $repo): bool => $repo['state'] === 'affected');
        $remaining = count(array_filter($repos, static fn (array $repo): bool => $repo['state'] !== 'fixed'));
        $allFixed = $repos !== [] && $remaining === 0;
        $mergeReopen = $finding['status'] === 'open' && ($snapshot['status'] ?? null) === 'dismissed';
        $status = $finding['status'];
        $closeTime = $finding['closed_by_gumshoe_at'];

        if ($task === [] && $finding['task_id'] > 0) {
            $status = 'dismissed';
            $closeTime = null;
            $this->sql("UPDATE gumshoe_findings SET status = 'dismissed', task_id = NULL, closed_by_gumshoe_at = NULL WHERE id = ?", [$findingId]);
            $finding['task_id'] = null;
        } elseif ($task !== [] && !(int) $task['is_active'] && (int) $task['date_completed'] > (int) $closeTime && !$mergeReopen) {
            $status = 'dismissed';
        }

        $reason = $status === 'dismissed' && $affected !== []
            ? $this->escalation($finding, $snapshot, $priority, $affected, $repoTransitions)
            : null;
        $reopen = $affected !== [] && (
            ($status === 'dismissed' && $reason !== null)
            || ($status === 'fixed' && $task !== [] && (int) $task['date_completed'] === (int) $closeTime)
            || $mergeReopen
        );
        if ($task === [] && (!$reopen && ($status !== 'open' || $affected === []))) {
            $this->persist($findingId, null, $previousProject, $status, $priority, $closeTime);
            $this->saveSnapshot($previousProject, $finding, $status);

            return null;
        }

        $project = $this->privateProject($task !== [] ? (int) $task['project_id'] :
            ($finding['task_id'] !== null ? $previousProject : $targetProject));
        if ($project === []) {
            return $this->unavailable($runId);
        }
        $projectId = (int) $project['id'];
        $values = [
            'title' => TaskText::title($finding['package'], $finding['primary_id'], $remaining),
            'description' => $this->description($finding),
            'priority' => Priority::toProject($priority, (int) $project['priority_start'], (int) $project['priority_end']),
        ];

        if ($task === []) {
            // Reconciliation already owns the unique finding row. Pin the
            // project before invoking core, whose after-save hook can throw.
            $creation = $this->createTask($finding, $targetProject, $projectId, $reference, $values, $snapshot);
            if (isset($creation['unavailable'])) {
                return $this->unavailable($runId);
            }
            if (isset($creation['interrupted'])) {
                throw $creation['interrupted'];
            }
            $task = $this->taskFinderModel->getById($creation['id']) ?: [];
            $this->check($task !== [], 'read created task');
        }
        $taskId = (int) $task['id'];

        $result = (new FindingModel($this->db->getConnection()))->transaction(function () use (
            $task, $taskId, $projectId, $targetProject, $finding, $repos, $repoTransitions, $status, $priority,
            $closeTime, $allFixed, $reopen, $reason, $values,
        ): array {
            if (!$this->lockPrivateProjects($targetProject, $projectId)) {
                return ['unavailable' => true];
            }
            if (!$this->lockTask($task)) {
                $current = $this->taskFinderModel->getById($taskId) ?: [];
                if ($current === [] || (!(int) $current['is_active'] && (int) $current['date_completed'] > (int) $closeTime)) {
                    $this->persist((int) $finding['id'], $current === [] ? null : $taskId, $projectId, 'dismissed', $priority, $closeTime);
                    $this->saveSnapshot($projectId, $finding, 'dismissed');
                    // The close wins this escalation, including any new repo.
                    $this->sql('UPDATE gumshoe_finding_repos SET subtask_id = 0 WHERE finding_id = ? AND subtask_id IS NULL', [$finding['id']]);
                }

                return [];
            }

            $active = (bool) $task['is_active'];
            // An interruption in a core subtask create may follow the insert.
            // Keep that insert, with its title as the retry key, before doing
            // any status or comment writes in this batch.
            try {
                $subtasks = $this->ensureSubtasks($taskId, $repos, $active && !$reopen);
            } catch (Throwable $error) {
                return ['interrupted' => $error];
            }

            if ($reopen) {
                if (!$active) {
                    $this->check($this->taskStatusModel->open($taskId), 'open task');
                }
                if ($reason !== null) {
                    $this->comment($taskId, "Reopened: $reason.");
                }
                $active = true;
            }
            if ($active) {
                $status = 'open';
                $closeTime = null;
            }

            if ($active || $status !== 'dismissed') {
                if (array_diff_assoc($values, array_intersect_key($task, $values)) !== []) {
                    $this->check($this->taskModificationModel->update(['id' => $taskId] + $values), 'update task');
                }
            }
            $this->syncSubtasks($taskId, $repos, $subtasks, $repoTransitions, $active);
            if ($allFixed && $status !== 'dismissed' && $active) {
                $this->comment($taskId, 'Fixed in all repos.');
                $this->check($this->taskStatusModel->close($taskId), 'close task');
                $closeTime = (int) $this->taskFinderModel->getById($taskId)['date_completed'];
                $status = 'fixed';
            }
            $this->persist((int) $finding['id'], $taskId, $projectId, $status, $priority, $closeTime);
            $this->saveSnapshot($projectId, $finding, $status);

            return [];
        });
        if (isset($result['interrupted'])) {
            throw $result['interrupted'];
        }

        return isset($result['unavailable']) ? $this->unavailable($runId) : null;
    }

    private function findTask(array $finding): array
    {
        $reference = 'gumshoe:finding:'.$finding['id'];
        if ($finding['task_id'] > 0) {
            $task = $this->taskFinderModel->getById((int) $finding['task_id']);

            return ($task['reference'] ?? null) === $reference ? $task : [];
        }
        if ($finding['task_id'] !== null && (int) $finding['project_id'] > 0) {
            $task = $this->taskFinderModel->getByReference((int) $finding['project_id'], $reference);
            if ($task) {
                return $task;
            }
            // A task can be moved after the core insert and before the link.
            $id = $this->sql('SELECT id FROM tasks WHERE reference = ? ORDER BY id LIMIT 1', [$reference])->fetchColumn();

            return $id === false ? [] : ($this->taskFinderModel->getById((int) $id) ?: []);
        }

        return [];
    }

    private function createTask(array $finding, int $target, int $project, string $reference, array $values, array $snapshot): array
    {
        return (new FindingModel($this->db->getConnection()))->transaction(function () use (
            $finding, $target, $project, $reference, $values, $snapshot,
        ): array {
            if (!$this->lockPrivateProjects($target, $project)) {
                return ['unavailable' => true];
            }
            if ($finding['task_id'] === null) {
                $claim = $this->sql(
                    'UPDATE gumshoe_findings SET task_id = 0, project_id = ? WHERE id = ? AND task_id IS NULL',
                    [$project, $finding['id']],
                );
                $this->check($claim->rowCount() === 1, 'claim finding');
                if ($snapshot !== [] && (int) $finding['project_id'] !== $project) {
                    $this->writeSnapshot($project, (int) $finding['id'], $snapshot);
                }
            }

            try {
                $id = $this->taskCreationModel->create($values + ['project_id' => $project, 'reference' => $reference]);
                $this->check($id > 0, 'create task');
            } catch (Throwable $error) {
                if (!$this->taskFinderModel->getByReference($project, $reference)) {
                    throw $error;
                }

                return ['interrupted' => $error];
            }

            return ['id' => (int) $id];
        });
    }

    private function repos(int $findingId): array
    {
        $rows = $this->sql(
            'SELECT fr.*, o.login AS owner, r.name AS repo
             FROM gumshoe_finding_repos fr JOIN gumshoe_repos r ON r.id = fr.repo_id
             JOIN gumshoe_owners o ON o.id = r.owner_id WHERE fr.finding_id = ? ORDER BY fr.repo_id',
            [$findingId],
        )->fetchAll(PDO::FETCH_ASSOC);
        foreach ($rows as &$row) {
            $row['title'] = TaskText::label($row['owner'].'/'.$row['repo']);
        }

        return array_column($rows, null, 'repo_id');
    }

    private function escalation(array $finding, array $snapshot, string $priority, array $affected, array $transitions): ?string
    {
        if ($finding['last_synced_at'] === null) {
            return null;
        }

        $rank = ['low' => 0, 'normal' => 1, 'high' => 2, 'urgent' => 3];
        $previousPriority = $rank[$finding['priority']];
        $knownMalware = !empty($snapshot['malware']);
        $knownKev = !empty($snapshot['kev']);
        $knownRepos = [];
        // Merging two dismissed findings combines evidence already seen on
        // either task. It does not itself create an escalation.
        $absorbed = $this->sql(
            "WITH RECURSIVE absorbed(id) AS (
                 SELECT id FROM gumshoe_groups WHERE merged_into = ?
                 UNION SELECT g.id FROM gumshoe_groups g JOIN absorbed a ON a.id = g.merged_into
             )
             SELECT f.* FROM gumshoe_findings f JOIN absorbed a ON a.id = f.group_id
             WHERE f.ecosystem = ? AND f.package = ? AND f.status = 'merged'",
            [$finding['group_id'], $finding['ecosystem'], $finding['package']],
        )->fetchAll(PDO::FETCH_ASSOC);
        foreach ($absorbed as $other) {
            $otherSnapshot = $this->snapshot($other);
            $knownMalware = $knownMalware || !empty($otherSnapshot['malware']);
            $knownKev = $knownKev || !empty($otherSnapshot['kev']);
            $previousPriority = max($previousPriority, $rank[$other['priority']]);
            $task = $this->findTask($other);
            if ($task !== []) {
                foreach ($this->subtaskModel->getAll((int) $task['id']) as $subtask) {
                    $knownRepos[$subtask['title']] = true;
                }
            }
        }

        if ($snapshot !== [] && (int) $finding['malware'] && !$knownMalware) {
            return 'now known malware';
        }
        if ($snapshot !== [] && (int) $finding['kev'] && !$knownKev) {
            return 'now on CISA KEV';
        }
        if ($rank[$priority] > $previousPriority) {
            return "priority rose to $priority";
        }
        foreach ($affected as $repoId => $repo) {
            if ($repo['subtask_id'] === null && empty($transitions[$repoId]['was_ever_affected']) && !isset($knownRepos[$repo['title']])) {
                return 'new repo affected: '.TaskText::repoInComment($repo['title']);
            }
        }

        return null;
    }

    private function ensureSubtasks(int $taskId, array $repos, bool $active): array
    {
        $existing = $this->subtaskModel->getAll($taskId);
        $byId = array_column($existing, null, 'id');
        $byTitle = array_column(array_reverse($existing), null, 'title');
        $subtasks = [];
        foreach ($repos as $repoId => $repo) {
            if (!(int) $repo['ever_affected']) {
                continue;
            }

            $title = $repo['title'];
            $subtask = $byId[$repo['subtask_id']] ?? $byTitle[$title] ?? null;
            if ($subtask === null) {
                $status = $active && $repo['state'] !== 'fixed' ? SubtaskModel::STATUS_TODO : SubtaskModel::STATUS_DONE;
                $id = $this->subtaskModel->create(['task_id' => $taskId, 'title' => $title, 'status' => $status]);
                $this->check($id !== false && $id > 0, 'create subtask');
                $subtask = ['id' => $id, 'title' => $title, 'status' => $status];
            }
            $subtasks[$repoId] = $subtask;
        }

        return $subtasks;
    }

    private function syncSubtasks(int $taskId, array $repos, array $subtasks, array $transitions, bool $active): void
    {
        foreach ($subtasks as $repoId => $subtask) {
            $repo = $repos[$repoId];
            $status = (int) $subtask['status'];
            $name = TaskText::repoInComment($repo['title']);
            $transition = $transitions[$repoId] ?? [];
            $values = [];
            if ($subtask['title'] !== $repo['title']) {
                $values['title'] = $repo['title'];
            }
            if ($repo['state'] === 'fixed' && $status !== SubtaskModel::STATUS_DONE) {
                $values['status'] = SubtaskModel::STATUS_DONE;
                $this->comment($taskId, "Fixed in $name.");
            } elseif ($repo['state'] === 'fixed' && (int) $repo['subtask_id'] > 0 && ($transition['to'] ?? null) === 'fixed') {
                $this->commentOnce($taskId, "Fixed in $name.");
            } elseif ($active && $repo['state'] === 'affected' && $status === SubtaskModel::STATUS_DONE) {
                $values['status'] = SubtaskModel::STATUS_TODO;
            }
            if ($values !== []) {
                $this->check($this->subtaskModel->update($values + ['id' => $subtask['id'], 'task_id' => $taskId]), 'update subtask');
            }
            if ((int) $repo['subtask_id'] !== (int) $subtask['id']) {
                $this->sql('UPDATE gumshoe_finding_repos SET subtask_id = ? WHERE finding_id = ? AND repo_id = ?',
                    [$subtask['id'], $repo['finding_id'], $repoId]);
            }

            if ($active && $repo['state'] === 'unknown' && ($transition['to'] ?? null) === 'unknown' && isset($transition['comment'])) {
                $outcome = str_contains($transition['comment'], '(inaccessible)') ? 'inaccessible' : 'out_of_watch';
                $this->commentOnce($taskId, "$name is no longer scanned ($outcome); its status is unknown.");
            }
        }
    }

    private function description(array $finding): string
    {
        $ids = array_column($this->sql('SELECT alias FROM gumshoe_group_aliases WHERE group_id = ? ORDER BY alias',
            [$finding['group_id']])->fetchAll(PDO::FETCH_ASSOC), 'alias');
        array_unshift($ids, $finding['primary_id']);
        $cache = new AdvisoryCache($this->db->getConnection());
        $summary = '';
        foreach (array_unique($ids) as $id) {
            $body = $cache->get('osv', $id)['body'] ?? $cache->get('github-malware', $id)['body'] ?? [];
            $text = $body['summary'] ?? $body['details'] ?? '';
            if (is_string($text) && $text !== '') {
                $summary = $text;
                break;
            }
        }
        $rows = $this->sql(
            'SELECT o.login, r.name, l.path, e.version, d.scope
             FROM gumshoe_exposures e JOIN gumshoe_lockfiles l ON l.id = e.lockfile_id AND l.repo_id = e.repo_id
             JOIN gumshoe_repos r ON r.id = e.repo_id JOIN gumshoe_owners o ON o.id = r.owner_id
             LEFT JOIN gumshoe_deps d ON d.lockfile_id = l.id AND d.ecosystem = ? AND d.name = ? AND d.version = e.version
             WHERE e.finding_id = ? AND e.active = 1',
            [$finding['ecosystem'], $finding['package'], $finding['id']],
        )->fetchAll(PDO::FETCH_ASSOC);
        $exposures = [];
        foreach ($rows as $row) {
            $exposures[] = [
                'repo' => $row['login'].'/'.$row['name'], 'path' => $row['path'],
                'version' => $row['version'], 'scope' => $row['scope'] ?? '',
            ];
        }

        return TaskText::description($summary, $ids, $exposures, (bool) $finding['malware'], (bool) $finding['kev']);
    }

    private function syncMerged(array $finding, int $targetProject, int $runId): ?string
    {
        $task = $this->findTask($finding);
        if ($task !== [] && $this->privateProject((int) $task['project_id']) === []) {
            return $this->unavailable($runId);
        }
        $group = (int) $finding['merged_into'];
        $seen = [(int) $finding['group_id'] => true];
        while ($group > 0 && !isset($seen[$group])) {
            $seen[$group] = true;
            $next = $this->sql('SELECT merged_into FROM gumshoe_groups WHERE id = ?', [$group])->fetchColumn();
            if ($next === null) {
                break;
            }
            $group = (int) $next;
        }
        $survivor = (int) $this->sql("SELECT id FROM gumshoe_findings WHERE group_id = ? AND ecosystem = ? AND package = ? AND status <> 'merged'",
            [$group, $finding['ecosystem'], $finding['package']])->fetchColumn();
        $this->check($survivor > 0, 'find merge survivor');

        $problem = $this->sync($survivor, $targetProject, $runId);
        if ($problem !== null || $task === []) {
            return $problem;
        }

        $survivorTask = (int) $this->sql('SELECT task_id FROM gumshoe_findings WHERE id = ?', [$survivor])->fetchColumn();
        if ($survivorTask === 0) {
            return null;
        }

        $result = (new FindingModel($this->db->getConnection()))->transaction(function () use ($task, $targetProject, $survivorTask, $finding): array {
            if (!$this->lockPrivateProjects($targetProject, (int) $task['project_id'])) {
                return ['unavailable' => true];
            }
            if (!$this->lockTask($task)) {
                return [];
            }

            $id = (int) $task['id'];
            $this->commentOnce($id, "Merged into #$survivorTask.");
            $closeTime = $finding['closed_by_gumshoe_at'];
            if ($task['is_active']) {
                $this->check($this->taskStatusModel->close($id), 'close merged task');
                $closeTime = (int) $this->taskFinderModel->getById($id)['date_completed'];
            }
            $this->persist((int) $finding['id'], $id, (int) $task['project_id'], 'merged', $finding['priority'], $closeTime);

            return [];
        });

        return isset($result['unavailable']) ? $this->unavailable($runId) : null;
    }

    private function privateProject(int $projectId): array
    {
        $project = $this->projectModel->getById($projectId) ?: [];

        return $project !== [] && (int) $project['is_public'] === 0 ? $project : [];
    }

    private function lockPrivateProjects(int $target, int $actual): bool
    {
        $ids = array_unique([$target, $actual]);
        sort($ids);
        foreach ($ids as $id) {
            if ($this->forUpdate() === '') {
                // SQLite has one writer. Acquire that lock before reading
                // visibility, so it cannot change before core writes.
                $this->sql('UPDATE projects SET is_public = is_public WHERE id = ?', [$id]);
            }
            if ($this->sql('SELECT id FROM projects WHERE id = ? AND is_public = 0'.$this->forUpdate(), [$id])->fetchColumn() === false) {
                return false;
            }
        }

        return true;
    }

    private function lockTask(array $task): bool
    {
        $params = [$task['id'], $task['project_id'], $task['is_active']];
        $params[] = $task['reference'];
        $where = 'id = ? AND project_id = ? AND is_active = ? AND reference = ? AND date_completed';
        if ($task['date_completed'] === null) {
            $where .= ' IS NULL';
        } else {
            $where .= ' = ?';
            $params[] = $task['date_completed'];
        }

        // Core's status/modification models update by ID. Keep this row locked
        // through their writes, and skip them if a person changed the snapshot.
        $guard = $this->sql('UPDATE tasks SET date_modification = date_modification WHERE '.$where, $params);
        if ($guard->rowCount() === 1) {
            return true;
        }

        // MariaDB counts changed rows for a no-op UPDATE.
        return $this->db->getConnection()->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql'
            && $this->sql('SELECT id FROM tasks WHERE '.$where.$this->forUpdate(), $params)->fetchColumn() !== false;
    }

    private function forUpdate(): string
    {
        return $this->db->getConnection()->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite' ? '' : ' FOR UPDATE';
    }

    private function persist(int $id, ?int $task, int $project, string $status, string $priority, ?int $closed): void
    {
        $this->sql(
            'UPDATE gumshoe_findings SET task_id = ?, project_id = ?, status = ?, priority = ?, closed_by_gumshoe_at = ?, last_synced_at = ?
             WHERE id = ?',
            [$task, $project ?: null, $status, $priority, $closed, time(), $id],
        );
    }

    private function snapshot(array $finding): array
    {
        // Board metadata holds the last observed flag bits, so they survive
        // task deletion. The finding row remains the identity and task mapping.
        $value = $this->sql('SELECT value FROM project_has_metadata WHERE project_id = ? AND name = ?',
            [$finding['project_id'], 'gumshoe:observed:'.$finding['id']])->fetchColumn();

        $snapshot = $value === false ? null : json_decode($value, true);

        return is_array($snapshot) ? $snapshot : [];
    }

    private function saveSnapshot(int $project, array $finding, string $status): void
    {
        if ($project !== 0 && $this->privateProject($project) !== []) {
            $this->writeSnapshot($project, (int) $finding['id'], [
                'status' => $status, 'malware' => (bool) $finding['malware'], 'kev' => (bool) $finding['kev'],
            ]);
        }
    }

    private function writeSnapshot(int $project, int $findingId, array $snapshot): void
    {
        // MetadataModel::save() commits any open transaction, including ours.
        $mysql = $this->db->getConnection()->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql';
        $upsert = $mysql ? 'ON DUPLICATE KEY UPDATE value = VALUES(value)'
            : 'ON CONFLICT (project_id, name) DO UPDATE SET value = excluded.value';
        $this->sql('INSERT INTO project_has_metadata (project_id, name, value) VALUES (?, ?, ?) '.$upsert,
            [$project, 'gumshoe:observed:'.$findingId, json_encode($snapshot, JSON_THROW_ON_ERROR)]);
    }

    private function unavailable(int $runId): string
    {
        $value = $this->sql('SELECT counts FROM gumshoe_runs WHERE id = ?', [$runId])->fetchColumn();
        $this->check($value !== false, 'record unavailable project for run');
        $counts = json_decode($value, true, flags: JSON_THROW_ON_ERROR);
        $counts['project_unavailable'] = ($counts['project_unavailable'] ?? 0) + 1;
        $this->sql('UPDATE gumshoe_runs SET counts = ? WHERE id = ?', [json_encode($counts, JSON_THROW_ON_ERROR), $runId]);

        return 'project_unavailable';
    }

    private function comment(int $taskId, string $text): void
    {
        $this->check($this->commentModel->create(['task_id' => $taskId, 'user_id' => 0, 'comment' => $text]) > 0, 'create comment');
    }

    private function commentOnce(int $taskId, string $text): void
    {
        $exists = $this->sql('SELECT id FROM comments WHERE task_id = ? AND user_id = 0 AND comment = ? LIMIT 1',
            [$taskId, $text])->fetchColumn();
        if ($exists === false) {
            $this->comment($taskId, $text);
        }
    }

    private function check(bool $success, string $operation): void
    {
        if (!$success) {
            throw new RuntimeException('Gumshoe could not '.$operation.'.');
        }
    }

    private function sql(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->db->getConnection()->prepare($sql);
        $statement->execute($parameters);

        return $statement;
    }
}
