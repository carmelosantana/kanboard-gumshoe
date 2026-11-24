<?php

namespace Kanboard\Plugin\Gumshoe\Model;

use Kanboard\Plugin\Gumshoe\Inventory\Differ;
use Kanboard\Plugin\Gumshoe\Inventory\ParseResult;
use PDO;
use PDOStatement;
use RuntimeException;
use Throwable;

final class InventoryStore
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    /**
     * Apply one repo inventory slice. Callers set treeComplete only when files
     * absent from this list are known to be absent from the repository.
     *
     * @param array{
     *     treeComplete: bool, headSha: ?string, treeSha: ?string,
     *     files: list<array{
     *         path: string, blob_sha: string, kind: string, parser_version: int,
     *         result: ParseResult|callable(): ParseResult
     *     }>
     * } $scan
     */
    public function apply(int $runId, int $repoId, array $scan): void
    {
        $this->pdo->beginTransaction();
        try {
            $repo = $this->execute('SELECT last_complete_at FROM gumshoe_repos WHERE id = ?', [$repoId])
                ->fetch(PDO::FETCH_ASSOC);
            if ($repo === false) {
                throw new RuntimeException('Inventory repository does not exist.');
            }

            $remaining = $this->execute('SELECT * FROM gumshoe_lockfiles WHERE repo_id = ?', [$repoId])
                ->fetchAll(PDO::FETCH_ASSOC);
            // Index by path hash for matching and leave unvisited files in the map.
            $remaining = array_column($remaining, null, 'path_hash');
            $complete = $scan['treeComplete'];
            $changes = [];
            foreach ($scan['files'] as $file) {
                $key = hash('sha256', $file['path']);
                $stored = $remaining[$key] ?? null;
                unset($remaining[$key]);

                $result = $file['result'];
                if ($stored !== null && $stored['status'] === 'ok' && $file['blob_sha'] === $stored['blob_sha']
                    && $file['kind'] === $stored['kind'] && $file['parser_version'] === (int) $stored['parser_version']
                    && (!$result instanceof ParseResult || $result->status === 'ok')) {
                    continue;
                }

                if (!$result instanceof ParseResult) {
                    $result = $result();
                }
                $ok = $result->status === 'ok';
                $lockfileId = $this->saveFile($repoId, $key, $file, $stored, $ok);
                if ($ok) {
                    array_push($changes, ...$this->replaceDependencies($lockfileId, $file['path'], $result));
                } else {
                    $complete = false;
                }
            }

            if ($scan['treeComplete']) {
                foreach ($remaining as $file) {
                    $this->execute('DELETE FROM gumshoe_lockfiles WHERE id = ?', [$file['id']]);
                    $changes[] = ['kind' => 'lockfile_gone', 'path' => $file['path']];
                }
            }

            $now = time();
            $firstComplete = $complete && $repo['last_complete_at'] === null;
            if ($firstComplete) {
                $this->recordChange($runId, $repoId, $now, ['kind' => 'new_repo']);
            }
            foreach ($changes as $change) {
                if (!$firstComplete || $change['kind'] !== 'added') {
                    $this->recordChange($runId, $repoId, $now, $change);
                }
            }

            $this->execute(
                'UPDATE gumshoe_repos SET head_sha = ?, tree_sha = ?, outcome = ?,
                    last_complete_at = COALESCE(?, last_complete_at) WHERE id = ?',
                [$scan['headSha'], $scan['treeSha'], $complete ? 'complete' : 'partial', $complete ? $now : null, $repoId],
            );
            $this->pdo->commit();
        } catch (Throwable $error) {
            if ($this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }

    private function saveFile(int $repoId, string $key, array $file, ?array $stored, bool $ok): int
    {
        $values = [
            $file['blob_sha'], $file['kind'], $ok ? 'ok' : 'stale', $file['parser_version'],
            $ok ? $file['blob_sha'] : ($stored['last_complete_blob_sha'] ?? null),
        ];
        if ($stored !== null) {
            $this->execute(
                'UPDATE gumshoe_lockfiles SET blob_sha = ?, kind = ?, status = ?, parser_version = ?,
                    last_complete_blob_sha = ? WHERE id = ?',
                [...$values, $stored['id']],
            );
            return (int) $stored['id'];
        }

        $this->execute(
            'INSERT INTO gumshoe_lockfiles (blob_sha, kind, status, parser_version, last_complete_blob_sha, repo_id, path_hash, path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)',
            [...$values, $repoId, $key, $file['path']],
        );
        return (int) $this->execute(
            'SELECT id FROM gumshoe_lockfiles WHERE repo_id = ? AND path_hash = ?',
            [$repoId, $key],
        )->fetchColumn();
    }

    private function replaceDependencies(int $lockfileId, string $path, ParseResult $result): array
    {
        $old = $this->execute(
            'SELECT ecosystem, name, version FROM gumshoe_deps WHERE lockfile_id = ? ORDER BY id', [$lockfileId],
        )->fetchAll(PDO::FETCH_ASSOC);
        foreach ($old as &$row) {
            $row['path'] = $path;
        }
        unset($row);

        $this->execute('DELETE FROM gumshoe_deps WHERE lockfile_id = ?', [$lockfileId]);
        $insert = $this->pdo->prepare(
            'INSERT INTO gumshoe_deps (lockfile_id, ecosystem, name, version, scope, source, query_type)
                VALUES (?, ?, ?, ?, ?, ?, ?)',
        );
        $new = [];
        foreach ($result->deps as $dependency) {
            $version = $dependency->version ?? 'unresolved';
            $insert->execute([
                $lockfileId, $dependency->ecosystem, $dependency->name, $version,
                $dependency->scope, $dependency->source, $dependency->query_type,
            ]);
            $new[] = ['ecosystem' => $dependency->ecosystem, 'name' => $dependency->name, 'version' => $version, 'path' => $path];
        }
        return Differ::diff($old, $new);
    }

    private function recordChange(int $runId, int $repoId, int $now, array $change): void
    {
        $this->execute(
            'INSERT INTO gumshoe_dep_changes (run_id, repo_id, created_at, kind, ecosystem, name, from_version, to_version, path)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)',
            [
                $runId, $repoId, $now, $change['kind'], $change['ecosystem'] ?? null, $change['name'] ?? null,
                $change['from_version'] ?? null, $change['to_version'] ?? null, $change['path'] ?? null,
            ],
        );
    }

    private function execute(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($parameters);
        return $statement;
    }
}
