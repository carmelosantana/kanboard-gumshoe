<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Run\WriterLease;
use PDO;
use PDOStatement;
use PHPUnit\Framework\TestCase;
use RuntimeException;

final class WriterLeaseTest extends TestCase
{
    public function testExpiredHolderCannotRenewReleaseOrWrite(): void
    {
        $file = tempnam(sys_get_temp_dir(), 'gumshoe-lease');
        try {
            $first = new PDO('sqlite:'.$file);
            $second = new class('sqlite:'.$file) extends PDO {
                public array $statements = [];

                public function prepare(string $query, array $options = []): PDOStatement|false
                {
                    $this->statements[] = $query;
                    return parent::prepare($query, $options);
                }

                public function query(string $query, ?int $fetchMode = null, mixed ...$fetchModeArgs): PDOStatement|false
                {
                    $this->statements[] = $query;
                    return parent::query($query, $fetchMode, ...$fetchModeArgs);
                }
            };
            $first->exec("CREATE TABLE gumshoe_state (name TEXT PRIMARY KEY, holder TEXT, lease_until BIGINT, run_id INTEGER);
                INSERT INTO gumshoe_state VALUES ('writer', NULL, 0, NULL)");
            $now = 100;
            $clock = static function () use (&$now): int { return $now; };
            $a = new WriterLease($first, $clock);
            $b = new WriterLease($second, $clock);
            self::assertTrue($a->claim('a', 10));
            self::assertFalse($b->claim('b', 10));
            self::assertCount(1, $second->statements);
            self::assertMatchesRegularExpression('/\AUPDATE .*lease_until < \?.*holder = \?/s', $second->statements[0]);
            $now = 111;
            self::assertFalse($a->renew('a', 10));
            self::assertTrue($b->claim('b', 10));
            self::assertFalse($a->release('a'));
            try {
                $a->write('a', static fn () => $first->exec("UPDATE gumshoe_state SET run_id = 99"));
                self::fail('Expired writer ran a durable batch.');
            } catch (RuntimeException) {
                self::assertNull($first->query("SELECT run_id FROM gumshoe_state WHERE name = 'writer'")->fetchColumn());
            }
            self::assertFalse($first->inTransaction());
            $b->write('b', static fn () => $second->exec("UPDATE gumshoe_state SET run_id = 1"));
            self::assertSame(1, (int) $first->query("SELECT run_id FROM gumshoe_state WHERE name = 'writer'")->fetchColumn());
            self::assertTrue($b->release('b'));
            self::assertTrue($a->claim('a', 10));
        } finally {
            unlink($file);
        }
    }
}
