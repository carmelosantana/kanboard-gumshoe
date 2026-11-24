<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Closure;
use Kanboard\Plugin\Gumshoe\Plugin;
use Kanboard\Plugin\Gumshoe\Run\RunLog;
use Kanboard\Plugin\Gumshoe\Run\Scanner;
use Kanboard\Plugin\Gumshoe\Run\VisitTrigger;
use Kanboard\Plugin\Gumshoe\Run\WriterLease;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use KanboardTests\units\Base;
use PDO;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';
require_once __DIR__.'/Fakes/FakeTransport.php';

final class VisitTriggerTest extends Base
{
    use ReleasesConnection;

    private PDO $pdo;
    private RunLog $log;
    private int $now = 1_800_000_000;
    private array $events = [];
    private ?Closure $shutdown = null;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $this->pdo = $this->container['db']->getConnection();
        version_1($this->pdo);
        $this->log = new RunLog($this->pdo);
        $inventory = $this->log->start('gumshoe.inventory', 'cli', 'done', $this->now);
        $this->log->finish((int) $inventory['id'], 'ok', $this->now);
        $this->container['gumshoeScanner'] = new Scanner($this->container, new FakeTransport(), 'https://example.com/', fn (): int => $this->now);
        $_SESSION['user'] = ['id' => 1];
    }

    public function testRenderedLayoutOnlySchedulesOnceAndFlushesBeforeScanning(): void
    {
        $this->container['gumshoeVisitTrigger'] = $this->trigger();
        (new Plugin($this->container))->initialize();
        $hook = $this->container['helper']->getHelper('hook');

        self::assertSame('', $hook->render('template:layout:top'));
        self::assertSame('', $hook->render('template:layout:top'));
        self::assertSame(['register'], $this->events);
        self::assertNotNull($this->shutdown);
        self::assertNull($this->log->latest('gumshoe.osv-recheck'));

        ($this->shutdown)();
        self::assertSame(['register', 'close session', 'finish response'], $this->events);
        self::assertSame('visit', $this->log->latest('gumshoe.osv-recheck')['trigger']);
        self::assertSame('ok', $this->log->latest('gumshoe.osv-recheck')['status']);
    }

    public function testVisitDoesNothingWithoutFastCgi(): void
    {
        self::assertFalse(function_exists('fastcgi_finish_request'));
        $this->trigger(false)->schedule();
        self::assertSame([], $this->events);
        self::assertNull($this->log->latest('gumshoe.osv-recheck'));
    }

    public function testVisitRequiresAuthenticationNoForemanDueWorkAndAFreeLease(): void
    {
        $trigger = $this->trigger();
        $_SESSION = [];
        $trigger->schedule();
        $_SESSION['user'] = ['id' => 1];
        $this->container['foreman'] = new \stdClass();
        $trigger->schedule();
        unset($this->container['foreman']);

        $this->pdo->exec('UPDATE gumshoe_settings SET hourly = 0');
        $trigger->schedule();
        $this->pdo->exec('UPDATE gumshoe_settings SET hourly = 1');

        $lease = new WriterLease($this->pdo, fn (): int => $this->now);
        self::assertTrue($lease->claim('cli-test', 60));
        $trigger->schedule();
        self::assertSame([], $this->events);
        self::assertNull($this->shutdown);
    }

    public function testShutdownRechecksWriterLeaseAndSkipsWorkIfResponseCannotFinish(): void
    {
        $this->trigger(finishes: false)->schedule();
        $lease = new WriterLease($this->pdo, fn (): int => $this->now);
        self::assertTrue($lease->claim('foreman-test', 60));
        ($this->shutdown)();
        self::assertSame(['register'], $this->events);
        self::assertNull($this->log->latest('gumshoe.osv-recheck'));

        self::assertTrue($lease->release('foreman-test'));
        $this->trigger(finishes: false)->schedule();
        ($this->shutdown)();
        self::assertSame(['register', 'register', 'close session', 'finish response'], $this->events);
        self::assertNull($this->log->latest('gumshoe.osv-recheck'));
    }

    public function testVisitBudgetStartsAfterTheResponseFinishes(): void
    {
        $this->pdo->exec("UPDATE gumshoe_runs SET finished_at = 1 WHERE job = 'gumshoe.inventory'");
        $scannerClock = $this->now + 50 + 10;
        $transport = new FakeTransport();
        $this->container['gumshoeScanner'] = new Scanner($this->container, $transport, 'https://example.com/', static fn (): int => $scannerClock);
        $this->trigger()->schedule();
        ($this->shutdown)();

        self::assertSame($scannerClock, $this->now + 10);
        self::assertSame([], $transport->requests);
        self::assertCount(1, $this->log->recent());
    }

    private function trigger(bool $fastCgi = true, bool $finishes = true): VisitTrigger
    {
        return new VisitTrigger(
            $this->container,
            clock: fn (): int => $this->now,
            registerShutdown: function (Closure $callback): void {
                $this->events[] = 'register';
                $this->shutdown = $callback;
            },
            closeSession: function (): void {
                $this->events[] = 'close session';
            },
            finishResponse: $fastCgi ? function () use ($finishes): bool {
                self::assertNull($this->log->latest('gumshoe.osv-recheck'));
                $this->events[] = 'finish response';
                $this->now += 50;
                return $finishes;
            } : null,
        );
    }
}
