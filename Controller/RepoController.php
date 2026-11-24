<?php

namespace Kanboard\Plugin\Gumshoe\Controller;

use Kanboard\Controller\BaseController;
use PDO;

final class RepoController extends BaseController
{
    public function show(): void
    {
        $id = filter_var($this->request->getStringParam('repo_id'), FILTER_VALIDATE_INT, ['options' => ['min_range' => 1]]);
        $repo = $id === false ? null : ($this->rows('SELECT o.login, r.name, r.outcome, r.last_complete_at
            FROM gumshoe_repos r JOIN gumshoe_owners o ON o.id = r.owner_id
            WHERE r.id = ? AND o.watch_id = 1', $id)[0] ?? null);
        if ($repo === null) {
            $this->response->html($this->helper->layout->app('app/notfound', ['title' => t('Page not found')]), 404);
            return;
        }

        $lockfiles = $this->rows('SELECT path, status FROM gumshoe_lockfiles WHERE repo_id = ? ORDER BY path, id', $id);
        $dependencyCounts = [];
        $gaps = ['private' => 0, 'denied' => 0, 'unqueryable' => 0];
        foreach ($this->rows('SELECT d.ecosystem, d.egress, COUNT(*) AS total
            FROM gumshoe_deps d JOIN gumshoe_lockfiles l ON l.id = d.lockfile_id
            WHERE l.repo_id = ? GROUP BY d.ecosystem, d.egress ORDER BY d.ecosystem', $id) as $row) {
            $ecosystem = $row['ecosystem'];
            $dependencyCounts[$ecosystem] = ($dependencyCounts[$ecosystem] ?? 0) + (int) $row['total'];
            if (isset($gaps[$row['egress']])) {
                $gaps[$row['egress']] += (int) $row['total'];
            }
        }
        $changes = $this->rows('SELECT kind, ecosystem, name, from_version, to_version, path, created_at
            FROM gumshoe_dep_changes WHERE repo_id = ? ORDER BY created_at DESC, id DESC LIMIT 100', $id);
        $findings = $this->rows("SELECT f.id, f.ecosystem, f.package, f.priority, g.primary_id, fr.state,
                t.id AS task_id, t.project_id, t.reference
            FROM gumshoe_finding_repos fr
            JOIN gumshoe_findings f ON f.id = fr.finding_id
            JOIN gumshoe_groups g ON g.id = f.group_id
            LEFT JOIN tasks t ON t.id = f.task_id
            WHERE fr.repo_id = ? AND fr.state IN ('affected', 'unknown') AND f.status = 'open'
            ORDER BY f.ecosystem, f.package, g.primary_id, f.id", $id);
        foreach ($findings as &$finding) {
            if ($finding['reference'] !== 'gumshoe:finding:'.$finding['id']) {
                $finding['task_id'] = null;
            }
        }
        unset($finding);

        $this->response->html($this->helper->layout->config('Gumshoe:repo/show',
            ['title' => 'Gumshoe · Repository'] + compact('repo', 'lockfiles', 'dependencyCounts', 'gaps', 'changes', 'findings')));
    }

    private function rows(string $sql, int $repoId): array
    {
        $query = $this->db->getConnection()->prepare($sql);
        $query->execute([$repoId]);

        return $query->fetchAll(PDO::FETCH_ASSOC);
    }
}
