<?php

namespace Kanboard\Plugin\Gumshoe\Model;

use PDO;

final class OwnerModel
{
    public function __construct(private readonly PDO $pdo)
    {
        if ($pdo->query('SELECT 1 FROM gumshoe_owners WHERE watch_id = 1 LIMIT 1')->fetchColumn() === false) {
            $this->seedDefaults();
        }
    }

    public function all(): array
    {
        return $this->pdo->query('SELECT * FROM gumshoe_owners WHERE watch_id = 1 ORDER BY id')->fetchAll(PDO::FETCH_ASSOC);
    }

    public function tokenRef(string $login): ?string
    {
        $statement = $this->pdo->prepare('SELECT token_ref FROM gumshoe_owners WHERE watch_id = 1 AND LOWER(login) = ?');
        $statement->execute([strtolower($login)]);
        $ref = $statement->fetchColumn();

        return is_string($ref) ? $ref : null;
    }

    private function seedDefaults(): void
    {
        $sql = <<<'SQL'
            INSERT INTO gumshoe_owners (watch_id, login, kind)
            VALUES (1, 'carmelosantana', 'user'), (1, 'AgentCoqui', 'org'), (1, 'VCTRSio', 'org'),
                   (1, 'ZoltarPredicts', 'org'), (1, 'beigebullet', 'org'), (1, 'AOM108-Inc', 'org')
            SQL;
        // Another request may have initialized the watch while this one was reading it.
        $onConflict = $this->pdo->getAttribute(PDO::ATTR_DRIVER_NAME) === 'mysql'
            ? ' ON DUPLICATE KEY UPDATE id = id'
            : ' ON CONFLICT (watch_id, login) DO NOTHING';
        $this->pdo->exec($sql.$onConflict);
    }
}
