<?php

namespace Kanboard\Plugin\Gumshoe\Model;

use PDO;
use RuntimeException;
use Throwable;

final class RepoModel
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function forOwner(int $ownerId): array
    {
        $statement = $this->pdo->prepare('SELECT * FROM gumshoe_repos WHERE owner_id = ? ORDER BY id');
        $statement->execute([$ownerId]);
        return $statement->fetchAll(PDO::FETCH_ASSOC);
    }

    /** Apply the snapshot from RepoLister as one unit. Inventory and watch modes belong to the existing GitHub id. */
    public function applyListing(int $ownerId, #[\SensitiveParameter] array $listing, int $now): void
    {
        if ($listing['status'] !== 'complete') {
            return;
        }

        $this->pdo->beginTransaction();
        try {
            $owner = $this->pdo->prepare('SELECT LOWER(login) FROM gumshoe_owners WHERE id = ? AND watch_id = 1');
            $owner->execute([$ownerId]);
            if ($owner->fetchColumn() !== $listing['owner']) {
                throw new RuntimeException('Discovery snapshot does not match the watch owner.');
            }
            $missing = array_column($this->forOwner($ownerId), 'id', 'github_id');

            $insert = $this->pdo->prepare(
                'INSERT INTO gumshoe_repos (owner_id, name, private, fork, archived, pushed_at, default_branch, github_id)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            );
            $update = $this->pdo->prepare(
                'UPDATE gumshoe_repos SET owner_id = ?, name = ?, private = ?, fork = ?, archived = ?,
                 pushed_at = ?, default_branch = ?, gone_at = NULL WHERE github_id = ?',
            );
            $find = $this->pdo->prepare('SELECT name FROM gumshoe_repos WHERE github_id = ?');
            $freeName = $this->pdo->prepare('UPDATE gumshoe_repos SET name = ? WHERE github_id = ?');
            $existing = [];
            foreach ($listing['repos'] as $repo) {
                $githubId = $repo['github_id'];
                $find->execute([$githubId]);
                $oldName = $find->fetchColumn();
                if ($oldName !== false) {
                    $existing[$githubId] = true;
                    if ($oldName !== $repo['name']) {
                        // Free the old name before another repo in this snapshot claims it.
                        $freeName->execute(['@'.$githubId, $githubId]);
                    }
                }
            }

            foreach ($listing['repos'] as $repo) {
                $githubId = $repo['github_id'];
                $values = [
                    $ownerId, $repo['name'], (int) $repo['private'], (int) $repo['fork'], (int) $repo['archived'],
                    $repo['pushed_at'], $repo['default_branch'], $githubId,
                ];

                (isset($existing[$githubId]) ? $update : $insert)->execute($values);
                unset($missing[$githubId]);
            }

            $markGone = $this->pdo->prepare('UPDATE gumshoe_repos SET gone_at = ? WHERE id = ? AND gone_at IS NULL');
            foreach ($missing as $repoId) {
                $markGone->execute([$now, $repoId]);
            }

            $this->pdo->commit();
        } catch (Throwable $error) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }
}
