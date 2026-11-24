<?php

namespace Kanboard\Plugin\Gumshoe\Advisory;

use PDO;

final readonly class AdvisoryCache
{
    public function __construct(private PDO $pdo)
    {
    }

    /** @return array{body: array, modified: ?string, fetched_at: int}|null */
    public function get(string $source, string $id): ?array
    {
        $statement = $this->pdo->prepare(
            'SELECT body, modified, fetched_at FROM gumshoe_advisory_cache WHERE source = ? AND advisory_id = ?'
        );
        $statement->execute([$source, $id]);
        $row = $statement->fetch(PDO::FETCH_ASSOC);
        return $row === false ? null : [
            'body' => json_decode($row['body'], true, flags: JSON_THROW_ON_ERROR),
            'modified' => $row['modified'],
            'fetched_at' => (int) $row['fetched_at'],
        ];
    }

    public function put(string $source, string $id, array $body, ?string $modified, int $fetchedAt): void
    {
        $upsert = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql'
            ? 'ON DUPLICATE KEY UPDATE modified = VALUES(modified), body = VALUES(body), fetched_at = VALUES(fetched_at)'
            : 'ON CONFLICT (source, advisory_id) DO UPDATE SET modified = excluded.modified, body = excluded.body, fetched_at = excluded.fetched_at';
        $statement = $this->pdo->prepare(
            'INSERT INTO gumshoe_advisory_cache (source, advisory_id, modified, body, fetched_at) VALUES (?, ?, ?, ?, ?) '.$upsert
        );
        $statement->execute([$source, $id, $modified, json_encode($body, JSON_THROW_ON_ERROR), $fetchedAt]);
    }
}
