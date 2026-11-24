<?php

namespace Kanboard\Plugin\Gumshoe\Advisory;

use InvalidArgumentException;
use PDO;
use PDOStatement;
use Throwable;

final readonly class GroupStore
{
    public function __construct(private PDO $pdo)
    {
    }

    /**
     * Resolve aliases under the scanner's writer lease. The returned merge ids
     * identify groups absorbed by this call. Their rows retain the merge target.
     *
     * @param non-empty-list<non-empty-string> $aliases
     * @return array{group: array{id: int, primary_id: string, cvss_max: ?float, malware: bool, kev: bool}, merged: list<int>}
     */
    public function resolve(array $aliases): array
    {
        if ($aliases === [] || in_array('', $aliases, true)) {
            throw new InvalidArgumentException('An advisory group needs at least one alias and all aliases must be non-empty.');
        }

        $aliases = array_values(array_unique($aliases));
        $placeholders = implode(', ', array_fill(0, count($aliases), '?'));
        $ownsTransaction = !$this->pdo->inTransaction();
        if ($ownsTransaction) {
            $this->pdo->beginTransaction();
        }
        try {
            $groups = $this->execute(
                "SELECT id, cvss_max, malware, kev FROM gumshoe_groups
                 WHERE id IN (SELECT group_id FROM gumshoe_group_aliases WHERE alias IN ($placeholders))
                 ORDER BY id",
                $aliases,
            )->fetchAll(PDO::FETCH_ASSOC);

            $merged = [];
            $cvss = null;
            $malware = false;
            $kev = false;

            if ($groups === []) {
                $primary = self::primaryId($aliases);
                $insert = 'INSERT INTO gumshoe_groups (primary_id) VALUES (?)';
                $id = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'pgsql'
                    ? (int) $this->execute($insert.' RETURNING id', [$primary])->fetchColumn()
                    : $this->insertGroup($insert, $primary);
                $newAliases = $aliases;
            } else {
                $id = (int) $groups[0]['id'];
                foreach ($groups as $group) {
                    $groupId = (int) $group['id'];
                    if ($groupId !== $id) {
                        $merged[] = $groupId;
                        $this->execute('UPDATE gumshoe_groups SET merged_into = ? WHERE id = ?', [$id, $groupId]);
                        $this->execute('UPDATE gumshoe_group_aliases SET group_id = ? WHERE group_id = ?', [$id, $groupId]);
                    }
                    if ($group['cvss_max'] !== null) {
                        $score = (float) $group['cvss_max'];
                        $cvss = $cvss === null ? $score : max($cvss, $score);
                    }
                    $malware = $malware || (bool) $group['malware'];
                    $kev = $kev || (bool) $group['kev'];
                }
                $storedAliases = $this->execute('SELECT alias FROM gumshoe_group_aliases WHERE group_id = ?', [$id])
                    ->fetchAll(PDO::FETCH_COLUMN);
                $newAliases = array_diff($aliases, $storedAliases);
                $primary = self::primaryId([...$storedAliases, ...$newAliases]);
                $this->execute(
                    'UPDATE gumshoe_groups SET primary_id = ?, cvss_max = ?, malware = ?, kev = ? WHERE id = ?',
                    [$primary, $cvss, (int) $malware, (int) $kev, $id],
                );
            }

            foreach ($newAliases as $alias) {
                $this->execute('INSERT INTO gumshoe_group_aliases (alias, group_id) VALUES (?, ?)', [$alias, $id]);
            }

            if ($ownsTransaction) {
                $this->pdo->commit();
            }
            return [
                'group' => ['id' => $id, 'primary_id' => $primary, 'cvss_max' => $cvss, 'malware' => $malware, 'kev' => $kev],
                'merged' => $merged,
            ];
        } catch (Throwable $error) {
            if ($ownsTransaction && $this->pdo->inTransaction()) {
                $this->pdo->rollBack();
            }
            throw $error;
        }
    }

    private static function primaryId(array $aliases): string
    {
        sort($aliases, SORT_STRING);
        foreach (['CVE-', 'GHSA-', 'MAL-'] as $prefix) {
            foreach ($aliases as $alias) {
                if (str_starts_with($alias, $prefix)) {
                    return $alias;
                }
            }
        }

        return $aliases[0];
    }

    private function insertGroup(string $sql, string $primary): int
    {
        $this->execute($sql, [$primary]);
        return (int) $this->pdo->lastInsertId();
    }

    private function execute(string $sql, array $parameters): PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($parameters);
        return $statement;
    }
}
