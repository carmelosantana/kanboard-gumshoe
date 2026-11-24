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
    private const MERGED_COMMENT_PATTERN = 'Merged into #%.';

    public const PUBLIC_BOARD_MESSAGE = 'The findings board is public; Gumshoe will not write private repo names to it.';

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
            return $this->unavailable($runId, $targetProject);
        }
        if ($finding['status'] === 'merged') {
            return $this->syncMerged($finding, $targetProject, $runId);
        }

        $reference = 'gumshoe:finding:'.$findingId;
        $task = $this->findTask($finding);
        $absorbed = $this->absorbedFindings($finding);
        if ($absorbed !== []) {
            $merge = $this->mergeBoardTasks($finding, $task, $absorbed, $targetProject, $reference);
            if (isset($merge['unavailable'])) {
                return $this->unavailable($runId, $targetProject, $merge['unavailable']);
            }
            if (isset($merge['retry'])) {
                return null;
            }
            [$finding, $task] = $merge;
        }

        $previousProject = (int) $finding['project_id'];
        $priority = Priority::of($finding);
        $repos = $this->repos($findingId);
        $affected = array_filter($repos, static fn (array $repo): bool => $repo['state'] === 'affected');
        $allFixed = $repos !== [] && array_all($repos, static fn (array $repo): bool => $repo['state'] === 'fixed');
        $status = $finding['status'];
        $closeTime = $finding['closed_by_gumshoe_at'];
        $personReopened = $finding['reopened_by_person_at'];

        $active = !empty($task['is_active']);
        if ($task === [] && $finding['task_id'] > 0) {
            $status = 'dismissed';
            $closeTime = null;
            $this->sql("UPDATE gumshoe_findings SET status = 'dismissed', task_id = NULL, closed_by_gumshoe_at = NULL WHERE id = ?", [$findingId]);
            $finding['task_id'] = null;
        } elseif ($task === [] && $finding['task_id'] === null && $previousProject > 0) {
            $status = 'dismissed';
        } elseif ($task !== [] && !$active && $this->wasClosedByPerson($finding, $task)) {
            $status = 'dismissed';
        } elseif ($active && $closeTime !== null) {
            $personReopened ??= time();
        }

        $reason = $status === 'dismissed'
            ? $this->escalation($finding, $priority, $affected, $repoTransitions, $absorbed)
            : null;
        if ($affected !== []) {
            $personReopened = null;
        }
        $reopen = $affected !== [] && (
            ($status === 'dismissed' && $reason !== null)
            || ($status === 'fixed' && $task !== [] && !$active && (int) $task['date_completed'] === (int) $closeTime)
        );
        if ($task === [] && !$reopen && ($status !== 'open' || $affected === [])) {
            $this->persist($finding, null, $previousProject, $status, $priority, $closeTime, $personReopened);

            return null;
        }

        $projectId = $task !== [] ? (int) $task['project_id'] :
            ($finding['task_id'] !== null ? $previousProject : $targetProject);
        $project = $this->privateProject($projectId);
        if ($project === []) {
            return $this->unavailable($runId, $targetProject, $projectId);
        }
        $values = [
            'description' => $this->description($finding),
            'priority' => Priority::toProject($priority, (int) $project['priority_start'], (int) $project['priority_end']),
        ];
        if ($affected !== [] || (!$allFixed && $active && $status === 'open')) {
            $values['title'] = TaskText::title($finding['package'], $finding['primary_id'], max(1, count($affected)));
        }

        if ($task === []) {
            // Reconciliation already owns the unique finding row. Pin the
            // project before invoking core, whose after-save hook can throw.
            $creation = $this->createTask($finding, $targetProject, $projectId, $reference, $values);
            if (isset($creation['unavailable'])) {
                return $this->unavailable($runId, $targetProject, $projectId);
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
            $closeTime, $allFixed, $reopen, $reason, $values, $personReopened,
        ): array {
            if (!$this->lockPrivateProjects($targetProject, $projectId)) {
                return ['unavailable' => $projectId];
            }
            if (!$this->lockTask($task)) {
                $current = $this->taskFinderModel->getById($taskId) ?: [];
                $currentProject = (int) ($current['project_id'] ?? $projectId);
                if ($this->privateProject($currentProject) === []) {
                    return ['unavailable' => $currentProject];
                }
                if ($current === [] || (empty($current['is_active']) && ((int) $current['date_completed'] > (int) $closeTime
                    || $finding['reopened_by_person_at'] !== null))) {
                    $this->persist($finding, $current === [] ? null : $taskId, $currentProject, 'dismissed', $priority, $closeTime, $personReopened);
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

            if ($reopen && !$active) {
                $this->check($this->taskStatusModel->open($taskId), 'open task');
                if ($reason !== null) {
                    $this->comment($taskId, "Reopened: $reason.");
                }
                $active = true;
            }
            if ($active && $personReopened === null) {
                $status = 'open';
                $closeTime = null;
            }

            $changes = $status === 'dismissed' && !$active ? [] : $values;
            if (array_diff_assoc($changes, array_intersect_key($task, $changes)) !== []) {
                $this->check($this->taskModificationModel->update(['id' => $taskId] + $changes), 'update task');
            }
            $this->syncSubtasks($taskId, $repos, $subtasks, $repoTransitions, $active, $active && $personReopened === null);
            if ($allFixed && $active && $personReopened === null) {
                $this->comment($taskId, 'Fixed in all repos.');
                $this->check($this->taskStatusModel->close($taskId), 'close task');
                $closeTime = (int) $this->taskFinderModel->getById($taskId)['date_completed'];
                $status = 'fixed';
            }
            $this->persist($finding, $taskId, $projectId, $status, $priority, $closeTime, $personReopened);

            return [];
        });
        if (isset($result['interrupted'])) {
            throw $result['interrupted'];
        }

        return isset($result['unavailable']) ? $this->unavailable($runId, $targetProject, $result['unavailable']) : null;
    }

    private function findTask(array $finding): array
    {
        $reference = 'gumshoe:finding:'.$finding['id'];
        if ($finding['task_id'] > 0) {
            $task = $this->taskFinderModel->getById((int) $finding['task_id']);

            return ($task['reference'] ?? null) === $reference ? $task : [];
        }
        if ($finding['task_id'] !== null && (int) $finding['project_id'] > 0) {
            // A person can move an interrupted create before recovery. This
            // project-scoped lookup accepts a duplicate in that window.
            return $this->recoverTask((int) $finding['project_id'], $reference);
        }

        return [];
    }

    private function recoverTask(int $project, string $reference): array
    {
        $task = $this->taskFinderModel->getByReference($project, $reference) ?: [];
        if ($task === [] || !$this->hasMergeComment((int) $task['id'])) {
            return $task;
        }

        // A replaced closed task keeps its original reference and history.
        return $this->sql(
            "SELECT t.* FROM tasks t WHERE t.project_id = ? AND t.reference = ?
             AND NOT EXISTS (SELECT 1 FROM comments c WHERE c.task_id = t.id AND c.user_id = 0 AND c.comment LIKE ?)
             ORDER BY t.id DESC LIMIT 1",
            [$project, $reference, self::MERGED_COMMENT_PATTERN],
        )->fetch(PDO::FETCH_ASSOC) ?: [];
    }

    private function createTask(array $finding, int $target, int $project, string $reference, array $values): array
    {
        return (new FindingModel($this->db->getConnection()))->transaction(function () use (
            $finding, $target, $project, $reference, $values,
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
            }

            try {
                $id = $this->taskCreationModel->create($values + ['project_id' => $project, 'reference' => $reference]);
                $this->check($id > 0, 'create task');
            } catch (Throwable $error) {
                if ($this->recoverTask($project, $reference) === []) {
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

    private function escalation(array $finding, string $priority, array $affected, array $transitions, array $absorbed): ?string
    {
        if ($finding['last_synced_at'] === null) {
            return null;
        }

        $rank = ['low' => 0, 'normal' => 1, 'high' => 2, 'urgent' => 3];
        $previousPriority = $rank[$finding['observed_priority'] ?? $finding['priority']];
        $knownMalware = !empty($finding['observed_malware']);
        $knownKev = !empty($finding['observed_kev']);
        // Severity already observed on either side of a merge is old evidence.
        foreach ($absorbed as $other) {
            if ($other['last_synced_at'] === null) {
                continue;
            }
            $knownMalware = $knownMalware || !empty($other['observed_malware']);
            $knownKev = $knownKev || !empty($other['observed_kev']);
            $previousPriority = max($previousPriority, $rank[$other['observed_priority'] ?? $other['priority']]);
        }

        $previouslyNonUrgent = $previousPriority < $rank['urgent'];
        if (($finding['observed_malware'] !== null || $previouslyNonUrgent) && (int) $finding['malware'] && !$knownMalware) {
            return 'now known malware';
        }
        if (($finding['observed_kev'] !== null || $previouslyNonUrgent) && (int) $finding['kev'] && !$knownKev) {
            return 'now on CISA KEV';
        }
        if ($rank[$priority] > $previousPriority) {
            return "priority rose to $priority";
        }
        foreach ($affected as $repoId => $repo) {
            if ($repo['subtask_id'] === null && empty($transitions[$repoId]['was_ever_affected'])) {
                return 'new repo affected: '.TaskText::repoInComment($repo['title']);
            }
        }

        return null;
    }

    private function absorbedFindings(array $finding): array
    {
        return $this->sql(
            "WITH RECURSIVE absorbed(id) AS (
                 SELECT id FROM gumshoe_groups WHERE merged_into = ?
                 UNION SELECT g.id FROM gumshoe_groups g JOIN absorbed a ON a.id = g.merged_into
             )
             SELECT f.* FROM gumshoe_findings f JOIN absorbed a ON a.id = f.group_id
             WHERE f.ecosystem = ? AND f.package = ? AND f.status = 'merged' ORDER BY f.id",
            [$finding['group_id'], $finding['ecosystem'], $finding['package']],
        )->fetchAll(PDO::FETCH_ASSOC);
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

    private function syncSubtasks(int $taskId, array $repos, array $subtasks, array $transitions, bool $active, bool $announceFix): void
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
                if ($announceFix) {
                    $this->comment($taskId, "Fixed in $name.");
                }
            } elseif ($announceFix && $repo['state'] === 'fixed' && (int) $repo['subtask_id'] > 0 && ($transition['to'] ?? null) === 'fixed') {
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

            $outcome = $transition['outcome'] ?? null;
            if ($active && $repo['state'] === 'unknown' && ($transition['to'] ?? null) === 'unknown'
                && in_array($outcome, ['inaccessible', 'out_of_watch'], true)) {
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

    private function wasClosedByPerson(array $finding, array $task): bool
    {
        return (int) $task['date_completed'] > (int) $finding['closed_by_gumshoe_at']
            || $finding['reopened_by_person_at'] !== null;
    }

    private function mergeBoardTasks(array $finding, array $kept, array $absorbed, int $target, string $reference): array
    {
        $active = [];
        $closed = [];
        foreach ($absorbed as $other) {
            $task = $this->findTask($other);
            if (!empty($task['is_active'])) {
                $active[] = [$other, $task];
            } elseif ($task !== [] && !$this->hasMergeComment((int) $task['id'])) {
                $closed[] = [$other, $task];
            }
        }

        foreach (array_merge($active, $closed) as [$other, $task]) {
            $adopt = !empty($task['is_active'])
                ? empty($kept['is_active'])
                : $kept === [] && $finding['task_id'] === null && $finding['project_id'] === null;
            if ($adopt) {
                $result = $this->adoptAbsorbedTask($finding, $kept, $other, $task, $target, $reference);
                if (isset($result['unavailable']) || isset($result['retry'])) {
                    return $result;
                }
                [$finding, $kept] = $result;
            } elseif ($kept !== []) {
                $status = 'open';
                if (empty($kept['is_active'])) {
                    $status = $finding['status'] === 'dismissed' || $other['observed_status'] === 'dismissed'
                        || $this->wasClosedByPerson($finding, $kept) || $this->wasClosedByPerson($other, $task)
                        ? 'dismissed' : 'fixed';
                }
                $result = $this->retireAbsorbedTask($other, $task, $kept, $target, (int) $finding['id'], $status);
                if ($result !== []) {
                    return $result;
                }
                $finding['status'] = $status;
            }
        }

        return [$finding, $kept];
    }

    private function adoptAbsorbedTask(array $finding, array $previous, array $absorbed, array $task, int $target, string $reference): array
    {
        $project = (int) $task['project_id'];
        $oldProject = (int) ($previous['project_id'] ?? $project);

        return (new FindingModel($this->db->getConnection()))->transaction(function () use (
            $finding, $previous, $absorbed, $task, $project, $oldProject, $target, $reference,
        ): array {
            if (!$this->lockPrivateProjects($target, $project, $oldProject)) {
                return ['unavailable' => $this->privateProject($project) === [] ? $project : $oldProject];
            }
            if (($previous !== [] && !$this->lockTask($previous)) || !$this->lockTask($task)) {
                return ['retry' => true];
            }

            $id = (int) $task['id'];
            $status = $task['is_active'] ? 'open' : 'dismissed';
            $personReopened = $task['is_active']
                ? ($absorbed['reopened_by_person_at'] ?? ($absorbed['closed_by_gumshoe_at'] !== null ? time() : null))
                : null;
            $claimWhere = $finding['task_id'] === null ? 'IS NULL' : '= ?';
            $claim = $this->sql(
                'UPDATE gumshoe_findings SET task_id = ?, project_id = ?, status = ?, closed_by_gumshoe_at = ?,
                 reopened_by_person_at = ?, last_synced_at = ?, observed_priority = ?, observed_malware = ?, observed_kev = ?, observed_status = ?
                 WHERE id = ? AND task_id '.$claimWhere,
                [
                    $id, $project, $status, $task['is_active'] ? null : $absorbed['closed_by_gumshoe_at'], $personReopened,
                    $finding['last_synced_at'] ?? $absorbed['last_synced_at'],
                    $finding['observed_priority'] ?? $absorbed['observed_priority'],
                    $finding['observed_malware'] ?? $absorbed['observed_malware'],
                    $finding['observed_kev'] ?? $absorbed['observed_kev'],
                    $finding['observed_status'] ?? $absorbed['observed_status'], $finding['id'],
                    ...($finding['task_id'] === null ? [] : [$finding['task_id']]),
                ],
            );
            $this->check($claim->rowCount() === 1, 'claim absorbed task');

            $affected = count(array_filter($this->repos((int) $finding['id']), static fn (array $repo): bool => $repo['state'] === 'affected'));
            if ($affected === 0 && preg_match('/\(([1-9][0-9]*) repos?\)$/D', $task['title'], $match)) {
                $affected = (int) $match[1];
            }
            $title = TaskText::title($finding['package'], $finding['primary_id'], max(1, $affected));
            $this->check($this->taskModificationModel->update([
                'id' => $id, 'reference' => $reference, 'title' => $title,
            ]), 'adopt absorbed task');
            if ($previous !== []) {
                $this->commentOnce((int) $previous['id'], "Merged into #$id.");
            }
            $this->sql('UPDATE gumshoe_findings SET task_id = NULL WHERE id = ?', [$absorbed['id']]);

            $updated = $this->sql('SELECT * FROM gumshoe_findings WHERE id = ?', [$finding['id']])->fetch(PDO::FETCH_ASSOC);

            return [$updated + $finding, ['reference' => $reference, 'title' => $title] + $task];
        });
    }

    private function retireAbsorbedTask(array $finding, array $task, array $kept, int $target, int $survivor, string $status): array
    {
        $project = (int) $task['project_id'];
        $keptProject = (int) $kept['project_id'];

        return (new FindingModel($this->db->getConnection()))->transaction(function () use (
            $finding, $task, $kept, $target, $project, $keptProject, $survivor, $status,
        ): array {
            if (!$this->lockPrivateProjects($target, $project, $keptProject)) {
                return ['unavailable' => $this->privateProject($project) === [] ? $project : $keptProject];
            }
            if (!$this->lockTask($kept) || !$this->lockTask($task)) {
                return ['retry' => true];
            }

            $id = (int) $task['id'];
            $this->commentOnce($id, "Merged into #{$kept['id']}.");
            $closeTime = $finding['closed_by_gumshoe_at'];
            if ($task['is_active']) {
                $this->check($this->taskStatusModel->close($id), 'close merged task');
                $closeTime = (int) $this->taskFinderModel->getById($id)['date_completed'];
            }
            $this->sql('UPDATE gumshoe_findings SET task_id = ?, project_id = ?, closed_by_gumshoe_at = ? WHERE id = ?',
                [$id, $project, $closeTime, $finding['id']]);
            $this->sql('UPDATE gumshoe_findings SET status = ? WHERE id = ?', [$status, $survivor]);

            return [];
        });
    }

    private function hasMergeComment(int $taskId): bool
    {
        return $this->sql('SELECT id FROM comments WHERE task_id = ? AND user_id = 0 AND comment LIKE ? LIMIT 1',
            [$taskId, self::MERGED_COMMENT_PATTERN])->fetchColumn() !== false;
    }

    private function syncMerged(array $finding, int $targetProject, int $runId): ?string
    {
        $group = (int) $finding['merged_into'];
        $seen = [(int) $finding['group_id'] => true];
        while ($group > 0 && !isset($seen[$group])) {
            $seen[$group] = true;
            $next = $this->sql('SELECT merged_into FROM gumshoe_groups WHERE id = ?', [$group])->fetchColumn();
            if ($next === null) {
                $survivor = (int) $this->sql("SELECT id FROM gumshoe_findings WHERE group_id = ? AND ecosystem = ? AND package = ? AND status <> 'merged'",
                    [$group, $finding['ecosystem'], $finding['package']])->fetchColumn();
                $this->check($survivor > 0, 'find merge survivor');

                return $this->sync($survivor, $targetProject, $runId);
            }
            $group = (int) $next;
        }

        throw new RuntimeException('Invalid advisory group merge chain.');
    }

    private function privateProject(int $projectId): array
    {
        $project = $this->projectModel->getById($projectId) ?: [];

        return $project !== [] && (int) $project['is_public'] === 0 ? $project : [];
    }

    private function lockPrivateProjects(int ...$projects): bool
    {
        $ids = array_unique($projects);
        sort($ids);
        foreach ($ids as $id) {
            if ($this->forUpdate() === '') {
                // SQLite has one writer. Acquire that lock before reading
                // visibility, so it cannot change before core writes.
                $this->sql('UPDATE projects SET is_public = is_public WHERE id = ?', [$id]);
            }
            if ($this->sql('SELECT id FROM projects WHERE id = ? AND is_public = ?'.$this->forUpdate(), [$id, 0])->fetchColumn() === false) {
                return false;
            }
        }

        return true;
    }

    private function lockTask(array $task): bool
    {
        $params = [$task['id'], $task['project_id'], (int) $task['is_active'], $task['reference']];
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

    private function persist(
        array $finding,
        ?int $task,
        int $project,
        string $status,
        string $priority,
        ?int $closed,
        ?int $personReopened,
    ): void {
        $this->sql(
            'UPDATE gumshoe_findings SET task_id = ?, project_id = ?, status = ?, priority = ?, closed_by_gumshoe_at = ?,
             reopened_by_person_at = ?, last_synced_at = ?, observed_priority = ?, observed_malware = ?, observed_kev = ?, observed_status = ?
             WHERE id = ?',
            [
                $task, $project ?: null, $status, $priority, $closed, $personReopened, time(),
                $priority, (int) $finding['malware'], (int) $finding['kev'], $status, $finding['id'],
            ],
        );
    }

    private function unavailable(int $runId, int ...$projects): string
    {
        $value = $this->sql('SELECT counts FROM gumshoe_runs WHERE id = ?', [$runId])->fetchColumn();
        $this->check($value !== false, 'record unavailable project for run');
        $counts = json_decode($value, true, flags: JSON_THROW_ON_ERROR);
        $counts['project_unavailable'] = ($counts['project_unavailable'] ?? 0) + 1;
        foreach (array_unique($projects) as $project) {
            $row = $this->projectModel->getById($project);
            if (!empty($row['is_public'])) {
                $counts['project_unavailable_message'] = self::PUBLIC_BOARD_MESSAGE;
                break;
            }
        }
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
