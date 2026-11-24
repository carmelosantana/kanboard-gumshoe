<?php

namespace Kanboard\Plugin\Gumshoe\Controller;

use InvalidArgumentException;
use Kanboard\Controller\BaseController;
use Kanboard\Core\Controller\AccessForbiddenException;
use Kanboard\Plugin\Gumshoe\Model\OwnerModel;
use Kanboard\Plugin\Gumshoe\Model\RepoModel;
use Kanboard\Plugin\Gumshoe\Model\SettingsModel;
use Kanboard\Plugin\Gumshoe\Run\Jobs;
use Kanboard\Plugin\Gumshoe\Run\RunLog;
use Kanboard\Plugin\Gumshoe\Secrets\Redactor;
use Kanboard\Plugin\Gumshoe\Watch\WatchRules;
use PDO;
use Throwable;

final class SourcesController extends BaseController
{
    private const PUBLIC_BOARD = 'The findings board is public; Gumshoe will not write private repo names to it.';
    private const FLAGS = ['scanning', 'hourly', 'forks', 'archived'];
    private const TOKEN_STATUSES = ['ok', 'expiring', 'expired', 'unknown', 'missing', 'refused'];

    public function index(): void
    {
        $state = $this->state();
        $pdo = $this->db->getConnection();
        $vault = $this->vault();
        $now = time();
        $rules = new WatchRules($state['settings'], $now);
        $counts = ['watched' => 0, 'total' => 0, 'pin' => 0, 'exclude' => 0];
        $tokens = array_fill_keys(self::TOKEN_STATUSES, 0);
        $coverage = $pdo->query("SELECT l.repo_id, d.egress, COUNT(*) AS total
            FROM gumshoe_deps d JOIN gumshoe_lockfiles l ON l.id = d.lockfile_id
            JOIN gumshoe_repos r ON r.id = l.repo_id JOIN gumshoe_owners o ON o.id = r.owner_id
            WHERE o.watch_id = 1 AND d.egress IN ('private', 'denied', 'unqueryable')
            GROUP BY l.repo_id, d.egress");
        $gaps = [];
        foreach ($coverage as $row) {
            $gaps[$row['repo_id']][$row['egress']] = (int) $row['total'];
        }

        foreach ($state['owners'] as &$owner) {
            $owner += $this->tokenInfo($owner, $vault, $now);
            $tokens[$owner['status']]++;
            $owner['watched'] = 0;
            foreach ($owner['repos'] as &$repo) {
                $repo['reason'] = $rules->reason($owner, $repo);
                $repo['watched'] = $rules->watched($owner, $repo);
                $repo['gaps'] = ($gaps[$repo['id']] ?? []) + ['private' => 0, 'denied' => 0, 'unqueryable' => 0];
                $counts['total']++;
                $counts['watched'] += (int) $repo['watched'];
                $owner['watched'] += (int) $repo['watched'];
                if ($repo['mode'] !== 'auto') {
                    $counts[$repo['mode']]++;
                }
            }
            unset($repo);
        }
        unset($owner);

        $findings = array_fill_keys(['urgent', 'high', 'normal', 'low'], 0);
        foreach ($pdo->query("SELECT priority, COUNT(*) AS total FROM gumshoe_findings WHERE status = 'open' GROUP BY priority") as $row) {
            $findings[$row['priority']] = (int) $row['total'];
        }
        $projects = $this->projectModel->getAll();
        $project = array_column($projects, null, 'id')[$state['settings']['project_id']] ?? null;
        $warning = !empty($project['is_public']) ? self::PUBLIC_BOARD : null;
        $log = new RunLog($pdo);
        $last = $log->recent(1)[0] ?? null;
        $next = $this->nextDue($log, $state['settings'], $vault, $now);
        $this->render('index', $state + compact('counts', 'tokens', 'findings', 'projects', 'project', 'warning', 'vault', 'last', 'next'));
    }

    public function review(): void
    {
        $this->submit('review');
    }

    public function owner(): void
    {
        $this->submit('owner');
    }

    public function importPins(): void
    {
        $this->submit('importPins');
    }

    public function save(): void
    {
        $this->submit('save');
    }

    private function submit(string $action): void
    {
        if (!$this->request->isPost()) {
            throw new AccessForbiddenException();
        }
        $this->checkCSRFForm();

        $values = $this->request->getRawFormValues();
        $before = $this->state();
        $vault = $this->vault();
        try {
            if (($action === 'owner' || array_key_exists('owner_id', $values))
                && !isset($before['owners'][$this->integer($values['owner_id'] ?? null, 1)])) {
                throw new AccessForbiddenException();
            }
            $revision = $this->integer($values['revision'] ?? null, 0);
            $changes = $this->changes($values, $before, $vault !== null);
            $unknown = [];
            if ($action === 'importPins') {
                $unknown = $this->stagePins($before, $changes, $values['pins'] ?? '');
            }
            $projectId = ($changes['settings'] + $before['settings'])['project_id'];
            $this->checkProject($projectId);
            $stale = $revision !== (int) $before['settings']['revision'];
            if ($action === 'save') {
                if ($this->persist($changes, $revision, $projectId)) {
                    $this->response->redirect($this->helper->url->href('SourcesController', 'index', ['plugin' => 'Gumshoe']));
                    return;
                }
                $before = $this->state();
                $changes = $this->changes($values, $before, $vault !== null);
                $stale = true;
            }
            $this->showReview($before, $changes, $vault, $unknown, $stale);
        } catch (InvalidArgumentException $error) {
            $this->render('review', ['error' => $error->getMessage()], 422);
        }
    }

    private function state(): array
    {
        $pdo = $this->db->getConnection();
        $settings = (new SettingsModel($pdo))->get();
        $owners = [];
        $repos = new RepoModel($pdo);
        foreach ((new OwnerModel($pdo))->all() as $owner) {
            $owner['repos'] = array_column($repos->forOwner((int) $owner['id']), null, 'id');
            $owners[$owner['id']] = $owner;
        }
        return compact('settings', 'owners');
    }

    private function changes(#[\SensitiveParameter] array $values, array $state, bool $vault): array
    {
        $settings = $owners = $repos = [];
        $input = $this->fields($values['settings'] ?? []);
        foreach (self::FLAGS as $name) {
            if (array_key_exists($name, $input)) {
                $settings[$name] = $this->integer($input[$name], 0, 1);
            }
        }
        if (array_key_exists('window_days', $input)) {
            $settings['window_days'] = $this->integer($input['window_days'], 1, 2147483647);
        }
        if (array_key_exists('project_id', $input)) {
            $settings['project_id'] = $this->integer($input['project_id'], 0) ?: null;
        }
        if (array_key_exists('deny_prefixes', $input)) {
            $prefixes = $input['deny_prefixes'];
            if (!is_string($prefixes) || str_contains($prefixes, "\0") || preg_match('//u', $prefixes) !== 1
                || Redactor::redact($prefixes) !== $prefixes) {
                throw new InvalidArgumentException('Enter valid deny prefixes.');
            }
            $settings['deny_prefixes'] = trim($prefixes);
        }

        foreach ($this->fields($values['owners'] ?? []) as $id => $input) {
            if (!isset($state['owners'][$id])) {
                throw new AccessForbiddenException();
            }
            $input = $this->fields($input);
            $owner = [];
            if (array_key_exists('enabled', $input)) {
                $owner['enabled'] = $this->integer($input['enabled'], 0, 1);
            }
            if (array_key_exists('token_ref', $input)) {
                $ref = is_string($input['token_ref']) ? trim($input['token_ref']) : null;
                if (!$vault || $ref === null || ($ref !== '' && !$this->validRef($ref))) {
                    throw new InvalidArgumentException('Use a Vault reference in the form vault://<int>/token with Server sharing on.');
                }
                $owner['token_ref'] = $ref === '' ? null : $ref;
            }
            $owners[$id] = $this->changedFields($owner, $state['owners'][$id]);
        }

        $currentRepos = $this->repos($state);
        foreach ($this->fields($values['repos'] ?? []) as $id => $mode) {
            if (!isset($currentRepos[$id])) {
                throw new AccessForbiddenException();
            }
            if (!in_array($mode, ['auto', 'pin', 'exclude'], true)) {
                throw new InvalidArgumentException('Choose Auto, Pin or Exclude for each repository.');
            }
            if ($currentRepos[$id]['mode'] !== $mode) {
                $repos[$id] = $mode;
            }
        }
        $settings = $this->changedFields($settings, $state['settings']);
        $owners = array_filter($owners);
        return compact('settings', 'owners', 'repos');
    }

    private function stagePins(array $state, array &$changes, #[\SensitiveParameter] mixed $input): array
    {
        if (!is_string($input)) {
            throw new InvalidArgumentException('Enter one repository per line.');
        }
        $names = [];
        $repos = $this->repos($state);
        foreach ($repos as $id => $repo) {
            $names[strtolower($repo['name'])][(string) $id] = $id;
            $names[strtolower($repo['full_name'])][(string) $id] = $id;
        }

        $unknown = [];
        foreach (preg_split('/\R/', $input) as $index => $line) {
            $line = trim($line);
            if ($line === '') {
                continue;
            }
            $name = preg_replace('~\Ahttps://github\.com/~i', '', $line);
            if (preg_match('~\A(?:[a-z0-9-]+/)?[a-z0-9_.-]+\z~i', $name) !== 1 || Redactor::redact($name) !== $name) {
                $unknown[] = 'Line '.($index + 1);
                continue;
            }
            $ids = $names[strtolower($name)] ?? [];
            if (count($ids) !== 1) {
                $unknown[] = $name;
                continue;
            }
            $id = reset($ids);
            unset($changes['repos'][$id]);
            if ($repos[$id]['mode'] !== 'pin') {
                $changes['repos'][$id] = 'pin';
            }
        }
        return array_unique($unknown);
    }

    private function showReview(array $before, array $changes, ?object $vault, array $unknown, bool $stale): void
    {
        $now = time();
        $oldRules = new WatchRules($before['settings'], $now);
        $newRules = new WatchRules($changes['settings'] + $before['settings'], $now);
        $added = $dropped = $references = $ownerChanges = $repoChanges = [];
        foreach ($before['owners'] as $id => $owner) {
            $ownerChange = $changes['owners'][$id] ?? [];
            $proposed = $ownerChange + $owner;
            if (isset($ownerChange['enabled'])) {
                $ownerChanges[$owner['login']] = $ownerChange['enabled'] ? 'Watching' : 'Off';
            }
            if (array_key_exists('token_ref', $ownerChange)) {
                $proposed['token_status'] = 'unknown';
                $proposed['token_expires_at'] = null;
                $references[$owner['login']] = $this->tokenInfo($proposed, $vault, $now);
            }
            foreach ($owner['repos'] as $repo) {
                $name = $owner['login'].'/'.$repo['name'];
                $mode = $changes['repos'][$repo['id']] ?? $repo['mode'];
                if ($mode !== $repo['mode']) {
                    $repoChanges[$name] = $mode;
                }
                $watched = $oldRules->watched($owner, $repo);
                $updated = $newRules->watched($proposed, ['mode' => $mode] + $repo);
                if ($updated && !$watched) {
                    $added[] = $name;
                } elseif ($watched && !$updated) {
                    $dropped[] = $name;
                }
            }
        }
        sort($added, SORT_NATURAL | SORT_FLAG_CASE);
        sort($dropped, SORT_NATURAL | SORT_FLAG_CASE);
        $boardName = isset($changes['settings']['project_id'])
            ? ($this->projectModel->getById($changes['settings']['project_id'])['name'] ?? 'Unavailable')
            : 'No board selected';
        $revision = $before['settings']['revision'];
        $this->render('review', compact('changes', 'added', 'dropped', 'references', 'unknown', 'revision', 'stale',
            'ownerChanges', 'repoChanges', 'boardName'), $stale ? 409 : 200);
    }

    private function persist(array $changes, int $revision, ?int $projectId): bool
    {
        $pdo = $this->db->getConnection();
        $pdo->beginTransaction();
        try {
            $set = implode('', array_map(static fn ($key) => ", $key = ?", array_keys($changes['settings'])));
            $update = $pdo->prepare('UPDATE gumshoe_settings SET revision = revision + 1'.$set.' WHERE watch_id = 1 AND revision = ?');
            $update->execute([...array_values($changes['settings']), $revision]);
            if ($update->rowCount() !== 1) {
                $pdo->rollBack();
                return false;
            }
            $this->checkProject($projectId, $pdo);

            foreach ($changes['owners'] as $id => $owner) {
                if (array_key_exists('token_ref', $owner)) {
                    $owner['token_status'] = $owner['token_ref'] === null ? 'missing' : 'unknown';
                    $owner['token_expires_at'] = null;
                }
                $set = implode(', ', array_map(static fn ($key) => "$key = ?", array_keys($owner)));
                $pdo->prepare("UPDATE gumshoe_owners SET $set WHERE id = ? AND watch_id = 1")
                    ->execute([...array_values($owner), $id]);
            }
            $updateRepo = $pdo->prepare('UPDATE gumshoe_repos SET mode = ?
                WHERE id = ? AND owner_id IN (SELECT id FROM gumshoe_owners WHERE watch_id = 1)');
            foreach ($changes['repos'] as $id => $mode) {
                $updateRepo->execute([$mode, $id]);
            }
            $pdo->commit();
            return true;
        } catch (Throwable $error) {
            $pdo->rollBack();
            throw $error;
        }
    }

    private function checkProject(?int $projectId, ?PDO $pdo = null): void
    {
        if ($projectId === null) {
            return;
        }
        if ($pdo === null) {
            $project = $this->projectModel->getById($projectId);
        } else {
            $lock = $pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'sqlite' ? '' : ' FOR UPDATE';
            $query = $pdo->prepare('SELECT is_public FROM projects WHERE id = ?'.$lock);
            $query->execute([$projectId]);
            $project = $query->fetch(PDO::FETCH_ASSOC);
        }
        if (empty($project)) {
            throw new InvalidArgumentException('Choose an existing findings board.');
        }
        if ((int) $project['is_public'] !== 0) {
            throw new InvalidArgumentException(self::PUBLIC_BOARD);
        }
    }

    private function vault(): ?object
    {
        try {
            $vault = $this->container['vaultSecrets'] ?? null;
            return $vault !== null && $vault->available() ? $vault : null;
        } catch (Throwable) {
            return null;
        }
    }

    private function tokenInfo(array $owner, ?object $vault, int $now): array
    {
        $status = $owner['token_status'];
        $refStatus = null;
        if (empty($owner['token_ref'])) {
            $status = 'missing';
        } elseif ($vault === null || !$this->validRef($owner['token_ref'])) {
            $status = 'refused';
        } else {
            try {
                $description = $vault->describe($owner['token_ref']);
                if (!$description->ok) {
                    $status = 'refused';
                    $refStatus = $description->reason;
                } else {
                    $refStatus = 'available';
                    if ($owner['token_expires_at'] !== null) {
                        $expires = (int) $owner['token_expires_at'];
                        $status = $expires <= $now ? 'expired' : ($expires <= $now + 14 * 86400 ? 'expiring' : 'ok');
                    }
                }
            } catch (Throwable) {
                $status = 'refused';
            }
        }
        return ['status' => in_array($status, self::TOKEN_STATUSES, true) ? $status : 'unknown', 'refStatus' => $refStatus];
    }

    private function validRef(#[\SensitiveParameter] string $ref): bool
    {
        return preg_match('~\Avault://[1-9][0-9]{0,17}/token\z~', $ref) === 1;
    }

    private function nextDue(RunLog $log, array $settings, ?object $vault, int $now): string
    {
        if (!(bool) $settings['scanning']) {
            return 'Paused';
        }
        if ($vault === null) {
            return 'Waiting for Vault';
        }
        $intervals = Jobs::INTERVALS;
        if (!(bool) $settings['hourly']) {
            unset($intervals[Jobs::RECHECK]);
        }
        $active = $log->active();
        $due = [];
        foreach ($intervals as $job => $interval) {
            $last = $log->latest($job);
            $due[$job] = $last === null ? $now : max((int) $last['finished_at'] + $interval, (int) $last['retry_at']);
        }
        $next = isset($intervals[$active['job'] ?? '']) ? (int) $active['retry_at'] : min($due);
        $time = $next <= $now ? 'Now' : $this->helper->dt->datetime($next);
        return $time.(isset($this->container['foreman']) ? ' via Foreman' : ' on a visit or CLI run');
    }

    private function repos(array $state): array
    {
        $repos = [];
        foreach ($state['owners'] as $owner) {
            foreach ($owner['repos'] as $id => $repo) {
                $repos[$id] = $repo + ['full_name' => $owner['login'].'/'.$repo['name']];
            }
        }
        return $repos;
    }

    private function changedFields(array $values, array $current): array
    {
        return array_filter($values, static fn ($value, $key) => $value !== null && is_int($value)
            ? $value !== (int) $current[$key]
            : $value !== $current[$key], ARRAY_FILTER_USE_BOTH);
    }

    private function fields(mixed $input): array
    {
        if (!is_array($input)) {
            throw new InvalidArgumentException('Invalid Sources form.');
        }
        return $input;
    }

    private function integer(mixed $input, int $min, int $max = PHP_INT_MAX): int
    {
        $value = filter_var($input, FILTER_VALIDATE_INT, ['options' => ['min_range' => $min, 'max_range' => $max]]);
        if ($value === false) {
            throw new InvalidArgumentException('Invalid numeric Sources setting.');
        }
        return $value;
    }

    private function render(string $page, array $data, int $status = 200): void
    {
        $this->response->html($this->helper->layout->config('Gumshoe:sources/'.$page, $data + ['title' => 'Gumshoe · Sources']), $status);
    }
}
