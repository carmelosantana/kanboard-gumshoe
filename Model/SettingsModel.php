<?php

namespace Kanboard\Plugin\Gumshoe\Model;

use PDO;
use RuntimeException;

final class SettingsModel
{
    public function __construct(private readonly PDO $pdo)
    {
    }

    public function get(): array
    {
        $settings = $this->pdo->query('SELECT * FROM gumshoe_settings WHERE watch_id = 1')->fetch(PDO::FETCH_ASSOC);
        if ($settings === false) {
            throw new RuntimeException('Gumshoe settings have not been initialized.');
        }
        return $settings;
    }
}
