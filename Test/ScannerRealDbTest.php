<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Run\WriterLease;
use KanboardTests\units\Base;
use PDO;
use RuntimeException;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';

final class ScannerRealDbTest extends Base
{
    use ReleasesConnection;

    public function testWriterTakeoverFencesAnIndependentConnection(): void
    {
        if (DB_DRIVER === 'sqlite') {
            self::markTestSkipped('The SQLite two-connection case runs in WriterLeaseTest.');
        }

        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $first = $this->container['db']->getConnection();
        version_1($first);
        $driver = DB_DRIVER === 'mysql' ? 'mysql' : 'pgsql';
        $second = new PDO($driver.':host='.DB_HOSTNAME.';dbname='.DB_NAME, DB_USERNAME, DB_PASSWORD);
        $now = 100;
        $clock = static function () use (&$now): int { return $now; };
        $a = new WriterLease($first, $clock);
        $b = new WriterLease($second, $clock);
        self::assertTrue($a->claim('inventory', 10));
        self::assertFalse($b->claim('recheck', 10));
        $now = 111;
        self::assertTrue($b->claim('recheck', 10));
        self::assertFalse($a->renew('inventory', 10));
        self::assertFalse($a->release('inventory'));
        try {
            $a->write('inventory', static fn () => $first->exec("UPDATE gumshoe_state SET run_id = 99"));
            self::fail('Expired writer ran a durable batch.');
        } catch (RuntimeException) {
            self::assertNull($second->query("SELECT run_id FROM gumshoe_state WHERE name = 'writer'")->fetchColumn());
        }
        $b->write('recheck', static fn () => $second->exec("UPDATE gumshoe_state SET run_id = 5"));
        self::assertSame(5, (int) $first->query("SELECT run_id FROM gumshoe_state WHERE name = 'writer'")->fetchColumn());
    }
}
