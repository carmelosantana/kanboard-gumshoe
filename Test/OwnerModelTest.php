<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Model\OwnerModel;
use Kanboard\Plugin\Gumshoe\Model\SettingsModel;
use KanboardTests\units\Base;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/ReleasesConnection.php';

final class OwnerModelTest extends Base
{
    use ReleasesConnection;

    public function testFreshWatchSeedsExactlyTheConfiguredOwnersOnce(): void
    {
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $pdo = $this->container['db']->getConnection();
        version_1($pdo);

        $settings = (new SettingsModel($pdo))->get();
        self::assertSame(90, (int) $settings['window_days']);
        self::assertSame(0, (int) $settings['forks']);
        self::assertSame(0, (int) $settings['archived']);

        $owners = new OwnerModel($pdo);
        $actual = [];
        foreach ($owners->all() as $owner) {
            $actual[$owner['login']] = [$owner['kind'], (int) $owner['enabled'], $owner['token_ref']];
        }
        self::assertEquals([
            'carmelosantana' => ['user', 1, null],
            'AgentCoqui' => ['org', 1, null],
            'VCTRSio' => ['org', 1, null],
            'ZoltarPredicts' => ['org', 1, null],
            'beigebullet' => ['org', 1, null],
            'AOM108-Inc' => ['org', 1, null],
        ], $actual);

        $pdo->exec("UPDATE gumshoe_owners SET enabled = 0, token_ref = 'vault://17/token' WHERE login = 'AgentCoqui'");
        $owners = new OwnerModel($pdo);
        self::assertCount(6, $owners->all());
        self::assertSame('vault://17/token', $owners->tokenRef('agentcoqui'));
        self::assertSame(0, (int) array_column($owners->all(), null, 'login')['AgentCoqui']['enabled']);
    }
}
