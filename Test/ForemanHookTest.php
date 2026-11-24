<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Plugin;
use Kanboard\Plugin\Gumshoe\Run\RunLog;
use Kanboard\Plugin\Gumshoe\Run\Scanner;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use KanboardTests\units\Base;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';
require_once __DIR__.'/Fakes/FakeTransport.php';

final class ForemanHookTest extends Base
{
    use ReleasesConnection;

    public function testListenersReturnExactlyTwoJobsWithTheStableResultContract(): void
    {
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $pdo = $this->container['db']->getConnection();
        version_1($pdo);
        $now = 1_800_000_000;
        $transport = new FakeTransport([new Response(503, ['Retry-After' => '1'])]);
        $this->container['gumshoeScanner'] = new Scanner($this->container, $transport, 'https://example.com/', static function () use (&$now): int {
            return $now;
        });

        (new Plugin($this->container))->initialize();
        $jobs = [];
        $this->container['hook']->merge('foreman:jobs', $jobs);
        self::assertSame(['gumshoe.inventory', 'gumshoe.osv-recheck'], array_column($jobs, 'id'));
        self::assertSame([86400, 3600], array_column($jobs, 'interval'));
        self::assertSame([10, 10], array_column($jobs, 'budget'));

        $log = new RunLog($pdo);
        $pdo->exec("INSERT INTO gumshoe_owners (login, kind, enabled) VALUES ('symfony', 'org', 0)");
        $run = $log->start('gumshoe.inventory', 'foreman', 'query', $now);
        $log->checkpoint((int) $run['id'], 'query', null, null, 'HttpFailure');
        $this->assertResult('more', $jobs[0]['run']($now));
        self::assertSame([], $transport->requests);
        $this->assertResult('failed', $jobs[0]['run']($now + 10));
        $this->assertResult('done', $jobs[1]['run']($now + 10));
        self::assertSame('foreman', $log->latest('gumshoe.osv-recheck')['trigger']);
    }

    private function assertResult(string $status, array $result): void
    {
        self::assertSame(['status', 'summary'], array_keys($result));
        self::assertSame($status, $result['status']);
        self::assertIsString($result['summary']);
    }
}
