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
use KanboardTests\units\Base;
use PDO;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';

final class RepoControllerTest extends Base
{
    use ReleasesConnection;

    private PDO $pdo;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $this->pdo = $this->container['db']->getConnection();
        version_1($this->pdo);
        $this->container['route']->enable();
        (new Plugin($this->container))->initialize();

        $this->pdo->exec("INSERT INTO gumshoe_owners (watch_id, login, kind) VALUES (1, 'symfony', 'org'), (2, 'laravel', 'org')");
        $this->pdo->exec("INSERT INTO gumshoe_repos (owner_id, name, github_id, outcome, last_complete_at) VALUES
            (1, 'symfony', 1, 'partial', 1700000000), (1, 'console', 2, 'complete', 1700000000),
            (2, 'framework', 3, NULL, NULL)");
        $_SESSION['user'] = $this->container['userModel']->getById(1);
    }

    public function testRepoPageRequiresAppAdminEvenForProjectManagers(): void
    {
        $project = $this->container['projectModel']->create(['name' => 'Dependencies']);
        $user = $this->container['userModel']->create(['username' => 'testuser', 'role' => Role::APP_USER]);
        $this->container['projectUserRoleModel']->addUser($project, $user, Role::PROJECT_MANAGER);
        $_SESSION['user'] = $this->container['userModel']->getById($user);

        $this->request('1', 403);
    }

    public function testUnknownInvalidAndOtherWatchIdsReturn404(): void
    {
        foreach (['999', 'bad', '3'] as $id) {
            $this->request($id, 404);
        }
    }

    public function testRepoPageShowsScopedInventoryHistoryAndFindings(): void
    {
        $project = $this->container['projectModel']->create(['name' => 'Dependencies']);
        $task = $this->container['taskCreationModel']->create([
            'title' => 'Open finding', 'project_id' => $project, 'reference' => 'gumshoe:finding:1',
        ]);
        $this->pdo->exec("INSERT INTO gumshoe_lockfiles (repo_id, path_hash, path, blob_sha, kind, status, parser_version) VALUES
            (1, 'a', 'composer.lock', 'a', 'composer', 'stale', 1),
            (1, 'b', '<img src=x>.json', 'b', 'npm', 'parse_error', 1),
            (2, 'c', 'other/composer.lock', 'c', 'composer', 'ok', 1)");
        $this->pdo->exec("INSERT INTO gumshoe_deps (lockfile_id, ecosystem, name, version, scope, egress) VALUES
            (1, 'Packagist', 'symfony/console', '7.3.0', 'prod', 'private'),
            (1, 'Packagist', 'symfony/yaml', '7.3.0', 'prod', 'denied'),
            (2, 'npm', 'lodash', '4.17.21', 'prod', 'unqueryable'),
            (2, 'npm', 'minimist', '1.2.8', 'prod', 'public'),
            (3, 'Packagist', 'symfony/finder', '7.3.0', 'prod', 'private')");
        $change = $this->pdo->prepare("INSERT INTO gumshoe_dep_changes
            (run_id, repo_id, kind, ecosystem, name, from_version, to_version, path, created_at)
            VALUES (1, ?, 'changed', 'npm', 'lodash', '4.17.20', '4.17.21', ?, 1700000000)");
        for ($i = 1; $i <= 101; $i++) {
            $change->execute([1, 'package-lock-'.$i.'.json']);
        }
        $change->execute([2, 'other/package-lock.json']);
        $this->pdo->exec("INSERT INTO gumshoe_groups (primary_id) VALUES
            ('GHSA-35jh-r3h4-6jhm'), ('GHSA-29mw-wpgm-hmr9'), ('GHSA-4qwp-7c67-jmcc'),
            ('GHSA-95w3-m7x3-5vj3')");
        $finding = $this->pdo->prepare("INSERT INTO gumshoe_findings
            (group_id, ecosystem, package, task_id, project_id, priority, status)
            VALUES (?, 'npm', ?, ?, ?, 'high', ?)");
        $finding->execute([1, 'lodash', $task, $project, 'open']);
        $finding->execute([2, 'minimist', null, null, 'dismissed']);
        $finding->execute([3, 'lodash', null, null, 'open']);
        $finding->execute([4, 'lodash', 99999, $project, 'open']);
        $this->pdo->exec("INSERT INTO gumshoe_finding_repos (finding_id, repo_id, state, ever_affected) VALUES
            (1, 1, 'unknown', 1), (2, 1, 'affected', 1), (3, 1, 'fixed', 1), (3, 2, 'affected', 1), (4, 1, 'affected', 1)");

        $page = $this->request('1', 200);
        $content = preg_replace('/\s+/', ' ', $page->evaluate('string(//section[@id="gumshoe-repo"])'));
        foreach (['symfony/symfony', 'partial', $this->container['helper']->dt->datetime(1700000000),
            'Packagist 2', 'npm 2', 'private 1', 'denied 1', 'unqueryable 1', 'composer.lock stale',
            '<img src=x>.json parse_error', 'changed npm lodash 4.17.20 4.17.21', 'GHSA-35jh-r3h4-6jhm',
            'GHSA-95w3-m7x3-5vj3', 'unknown'] as $detail) {
            self::assertStringContainsString($detail, $content);
        }
        foreach (['other/composer.lock', 'other/package-lock.json', 'package-lock-1.json', 'GHSA-29mw-wpgm-hmr9',
            'GHSA-4qwp-7c67-jmcc'] as $detail) {
            self::assertStringNotContainsString($detail, $content);
        }
        $history = $page->query('//table[caption="Recent dependency changes"]/tbody/tr');
        self::assertCount(100, $history);
        self::assertStringContainsString('package-lock-101.json', $history->item(0)->textContent);
        self::assertStringContainsString('package-lock-2.json', $history->item(99)->textContent);
        self::assertCount(0, $page->query('//section[@id="gumshoe-repo"]//img'));
        $taskUrl = $this->container['helper']->url->href('TaskViewController', 'show', ['task_id' => $task, 'project_id' => $project]);
        self::assertSame(html_entity_decode($taskUrl), $page->evaluate('string(//a[normalize-space(.)="#'.$task.'"]/@href)'));
        self::assertCount(0, $page->query('//a[normalize-space(.)="#99999"]'));
    }

    public function testSourcesLinksToRepoPage(): void
    {
        $page = $this->get('/settings/gumshoe/sources', 200, 'SourcesController', 'index');
        self::assertSame('/settings/gumshoe/repos/1', $page->evaluate('string(//a[normalize-space(.)="symfony"]/@href)'));
    }

    private function request(string $id, int $status): DOMXPath
    {
        return $this->get('/settings/gumshoe/repos/'.$id, $status, 'RepoController', 'show');
    }

    private function get(string $path, int $status, string $controller, string $action): DOMXPath
    {
        $this->container['request'] = new Request($this->container, [
            'REQUEST_METHOD' => 'GET', 'REQUEST_URI' => $path, 'SCRIPT_NAME' => '/index.php',
        ]);
        $this->container['router']->dispatch();
        self::assertSame($controller, $this->container['router']->getController());
        self::assertSame($action, $this->container['router']->getAction());

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
