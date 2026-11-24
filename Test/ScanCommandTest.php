<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Plugin;
use Kanboard\Plugin\Gumshoe\Run\RunLog;
use Kanboard\Plugin\Gumshoe\Run\Scanner;
use Kanboard\Plugin\Gumshoe\Run\WriterLease;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeVaultSecrets;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use KanboardTests\units\Base;
use PDO;
use Symfony\Component\Console\Tester\ApplicationTester;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';
require_once __DIR__.'/Fakes/FakeTransport.php';
require_once __DIR__.'/Fakes/FakeVaultSecrets.php';

final class ScanCommandTest extends Base
{
    use ReleasesConnection;

    private PDO $pdo;
    private RunLog $log;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $this->pdo = $this->container['db']->getConnection();
        version_1($this->pdo);
        $this->pdo->exec("INSERT INTO gumshoe_owners (login, kind, token_ref) VALUES ('symfony', 'org', 'vault://17/token')");
        $this->container['vaultSecrets'] = new FakeVaultSecrets(static fn () => SecretValue::of(bin2hex(random_bytes(20))));
        $this->log = new RunLog($this->pdo);
    }

    public function testDefaultRunsBothDueJobsAndSkipsThemOnTheNextInvocation(): void
    {
        $transport = new FakeTransport([
            new Response(200, [], '[]'),
            new Response(200, [], '[]'),
            new Response(200, [], '[]'),
            new Response(200, [], file_get_contents(__DIR__.'/fixtures/kev/known_exploited_vulnerabilities.json')),
        ]);
        $command = $this->command($transport);

        self::assertSame(0, $command->run(['command' => 'gumshoe:scan']));
        self::assertSame(['gumshoe.osv-recheck', 'gumshoe.inventory'], array_column($this->log->recent(), 'job'));
        self::assertSame(['ok', 'ok'], array_column($this->log->recent(), 'status'));
        self::assertSame(['cli', 'cli'], array_column($this->log->recent(), 'trigger'));
        self::assertSame(0, $command->run(['command' => 'gumshoe:scan']));
        self::assertCount(2, $this->log->recent());
        self::assertCount(4, $transport->requests);
    }

    public function testExplicitJobUsesTheSameWriterLeaseAndRunsOnlyThatJob(): void
    {
        $command = $this->command(new FakeTransport());
        $options = ['command' => 'gumshoe:scan', '--job' => 'gumshoe.osv-recheck'];
        $lease = new WriterLease($this->pdo);

        self::assertTrue($lease->claim('foreman-test', 60));
        self::assertSame(0, $command->run($options));
        self::assertStringContainsString('Another writer holds the scan lease.', $command->getDisplay());
        self::assertSame([], $this->log->recent());

        self::assertTrue($lease->release('foreman-test'));
        self::assertSame(0, $command->run($options));
        self::assertSame(['gumshoe.osv-recheck'], array_column($this->log->recent(), 'job'));
        self::assertSame('ok', $this->log->latest('gumshoe.osv-recheck')['status']);
    }

    public function testCliResumesAfterBackoffAndExitsNonzeroOnFailure(): void
    {
        $unavailable = new Response(503, ['Retry-After' => '1']);
        $transport = new FakeTransport([new Response(200, [], '[]'), $unavailable, $unavailable]);
        $command = $this->command($transport);

        self::assertSame(1, $command->run(['command' => 'gumshoe:scan']));
        self::assertCount(3, $transport->requests);
        self::assertSame('failed', $this->log->latest('gumshoe.inventory')['status']);
        self::assertSame('ok', $this->log->latest('gumshoe.osv-recheck')['status']);
        self::assertStringContainsString('The scan failed.', $command->getDisplay());
    }

    private function command(FakeTransport $transport): ApplicationTester
    {
        $this->container['gumshoeScanner'] = new Scanner($this->container, $transport, 'https://example.com/');
        (new Plugin($this->container))->initialize();
        $app = $this->container['cli'];
        $app->setAutoExit(false);
        return new ApplicationTester($app);
    }
}
