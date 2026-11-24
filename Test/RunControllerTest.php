<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use DOMDocument;
use DOMXPath;
use Kanboard\Core\Controller\Runner;
use Kanboard\Core\Http\Request;
use Kanboard\Core\Http\Response;
use Kanboard\Core\Security\Role;
use Kanboard\Middleware\ApplicationAuthorizationMiddleware;
use Kanboard\Plugin\Gumshoe\Plugin;
use Kanboard\Plugin\Gumshoe\Run\Jobs;
use Kanboard\Plugin\Gumshoe\Run\RunLog;
use KanboardTests\units\Base;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';

final class RunControllerTest extends Base
{
    use ReleasesConnection;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        version_1($this->container['db']->getConnection());
        $this->container['route']->enable();
        (new Plugin($this->container))->initialize();
    }

    public function testRunLogRequiresAppAdmin(): void
    {
        $user = $this->container['userModel']->create(['username' => 'testuser', 'role' => Role::APP_USER]);
        $_SESSION['user'] = $this->container['userModel']->getById($user);
        $this->request('/settings/gumshoe/run-log', 403);
    }

    public function testNewestFiftyRunsShowPersistedDetails(): void
    {
        $_SESSION['user'] = $this->container['userModel']->getById(1);
        $log = new RunLog($this->container['db']->getConnection());
        for ($i = 0; $i < 50; $i++) {
            $log->start(Jobs::RECHECK, 'foreman', 'query', 1700000000);
        }
        $run = $log->start(Jobs::INVENTORY, 'cli', 'inventory', 1700000000);
        $log->saveCounts($run['id'], ['complete' => 7, 'partial' => 3, 'inaccessible' => 2, 'failed_owners' => [99]]);
        $log->finish($run['id'], 'failed', 1700000010, \RuntimeException::class, 1700003600);

        $page = $this->request('/settings/gumshoe/run-log', 200);
        $rows = $page->query('//table/tbody/tr');
        self::assertCount(50, $rows);
        self::assertStringContainsString('51', $rows->item(0)->firstElementChild->textContent);
        self::assertSame('2', trim($rows->item(49)->firstElementChild->textContent));
        $retry = $this->container['helper']->dt->datetime(1700003600);
        $details = preg_replace('/\s+/', ' ', $rows->item(0)->textContent);
        foreach ([Jobs::INVENTORY, 'cli', 'inventory', 'failed', '7 complete', '3 partial',
            '2 inaccessible', 'Owners failed 1', $retry, 'RuntimeException'] as $detail) {
            self::assertStringContainsString($detail, $details);
        }
        self::assertSame('/settings/gumshoe/run-log', $page->evaluate('string(//a[normalize-space(.)="Gumshoe · Run log"]/@href)'));
    }

    private function request(string $path, int $status): DOMXPath
    {
        $this->container['request'] = new Request($this->container, [
            'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $path, 'SCRIPT_NAME' => '/index.php',
        ]);
        $this->container['router']->dispatch();
        self::assertSame('RunController', $this->container['router']->getController());
        self::assertSame('index', $this->container['router']->getAction());

        $html = '';
        $response = $this->createMock(Response::class);
        $response->expects(self::once())->method('html')->with(self::isType('string'), $status)
            ->willReturnCallback(static function ($body) use (&$html): void {
                $html = $body;
            });
        $this->container['response'] = $response;
        (new class($this->container) extends Runner {
            protected function executeMiddleware(): void
            {
                (new ApplicationAuthorizationMiddleware($this->container))->execute();
            }
        })->execute();
        $document = new DOMDocument();
        $document->loadHTML('<?xml encoding="UTF-8">'.$html, LIBXML_NOERROR | LIBXML_NOWARNING);

        return new DOMXPath($document);
    }
}
