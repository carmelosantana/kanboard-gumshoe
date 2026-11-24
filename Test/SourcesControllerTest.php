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

final class SourcesControllerTest extends Base
{
    use ReleasesConnection;

    private PDO $pdo;
    private int $status;
    private string $html;
    private int $publicProject;
    private int $privateProject;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $this->pdo = $this->container['db']->getConnection();
        version_1($this->pdo);
        $this->pdo->exec("INSERT INTO gumshoe_owners (watch_id, login, kind) VALUES
            (1, 'symfony', 'org'), (2, 'laravel', 'org')");
        $insert = $this->pdo->prepare('INSERT INTO gumshoe_repos (owner_id, name, github_id, pushed_at, outcome) VALUES (?, ?, ?, ?, ?)');
        $insert->execute([1, 'symfony', 1, time(), 'partial']);
        $insert->execute([1, 'console', 2, 1, 'inaccessible']);
        $insert->execute([1, '</script>"&\'', 3, time(), 'no_lockfile']);
        $insert->execute([2, 'framework', 4, time(), null]);
        $this->privateProject = $this->container['projectModel']->create(['name' => 'Dependencies']);
        $this->publicProject = $this->container['projectModel']->create(['name' => 'Shared project', 'is_public' => 1]);

        $_SESSION['user'] = $this->container['userModel']->getById(1);
        $response = $this->createMock(Response::class);
        $response->method('html')->willReturnCallback(function ($html, $status = 200): void {
            $this->html = $html;
            $this->status = $status;
        });
        $response->method('redirect')->willReturnCallback(function (): void {
            $this->status = 302;
        });
        $this->container['response'] = $response;
    }

    public static function restrictedRoutes(): iterable
    {
        foreach (['index', 'review', 'save', 'owner', 'importPins'] as $action) {
            yield $action.' (project manager)' => [$action, true];
            yield $action.' (user)' => [$action, false];
        }
    }

    /** @dataProvider restrictedRoutes */
    public function testDirectRoutesRequireAppAdmin(string $action, bool $projectManager): void
    {
        $user = $this->container['userModel']->create(['username' => 'testuser', 'role' => Role::APP_USER]);
        if ($projectManager) {
            $this->container['projectUserRoleModel']->addUser($this->privateProject, $user, Role::PROJECT_MANAGER);
        }
        $_SESSION['user'] = $this->container['userModel']->getById($user);

        $this->request($action, $action === 'index' ? 'GET' : 'POST', [
            'revision' => '0', 'owner_id' => '1', 'pins' => 'console',
            'settings' => ['project_id' => (string) $this->privateProject],
        ], params: ['project_id' => $this->privateProject]);
        self::assertSame(403, $this->status);
    }

    public static function formActions(): iterable
    {
        foreach (['save', 'owner', 'importPins'] as $action) {
            yield [$action, 'GET', true];
            yield [$action, 'POST', false];
        }
    }

    /** @dataProvider formActions */
    public function testMutationsRequirePostAndFormCsrf(string $action, string $method, bool $csrf): void
    {
        $this->request($action, $method, [
            'revision' => '0', 'settings' => ['window_days' => '1'], 'owner_id' => '1',
            'owners' => [1 => ['enabled' => '0']], 'pins' => 'symfony/console',
        ], $csrf);
        self::assertSame(403, $this->status);
        self::assertSame(0, $this->revision());
        self::assertSame('auto', $this->mode(2));
        self::assertSame(1, (int) $this->pdo->query('SELECT enabled FROM gumshoe_owners WHERE id = 1')->fetchColumn());
    }

    public function testReviewIsReadOnlyAndSaveRejectsStaleRevision(): void
    {
        $changes = ['revision' => '0', 'settings' => ['project_id' => (string) $this->privateProject],
            'repos' => [1 => 'exclude', 2 => 'pin']];
        $this->request('review', 'POST', $changes);
        self::assertSame(200, $this->status);
        foreach (['Added repos', 'symfony/console', 'Dropped repos', 'symfony/symfony'] as $label) {
            self::assertStringContainsString($label, $this->html);
        }
        self::assertSame(0, $this->revision());
        self::assertSame('auto', $this->mode(1));

        $this->pdo->exec('UPDATE gumshoe_settings SET revision = 1');
        $this->request('save', 'POST', $changes);
        self::assertSame(409, $this->status);
        self::assertStringContainsString('Sources changed', $this->html);
        self::assertStringContainsString('Added repos', $this->html);
        self::assertSame('1', $this->xpath()->evaluate('string(//input[@name="revision"]/@value)'));
        self::assertSame('auto', $this->mode(1));
        self::assertSame(1, $this->revision());

        $changes['revision'] = '1';
        $this->request('save', 'POST', $changes);
        self::assertSame(302, $this->status);
        self::assertSame('exclude', $this->mode(1));
        self::assertSame('pin', $this->mode(2));
        self::assertSame(2, $this->revision());
        self::assertSame($this->privateProject, (int) $this->pdo->query('SELECT project_id FROM gumshoe_settings')->fetchColumn());
    }

    public function testRejectsPublicProjectAndIdsFromAnotherWatch(): void
    {
        $this->request('save', 'POST', ['revision' => '0', 'settings' => ['project_id' => (string) $this->publicProject]]);
        self::assertSame(422, $this->status);
        self::assertStringContainsString('The findings board is public; Gumshoe will not write private repo names to it.', $this->html);

        foreach ([
            ['save', ['repos' => [4 => 'exclude']]],
            ['save', ['owners' => [2 => ['enabled' => '0']]]],
            ['owner', ['owner_id' => '2']],
        ] as [$action, $values]) {
            $this->request($action, 'POST', ['revision' => '0'] + $values);
            self::assertSame(403, $this->status);
        }
        self::assertSame('auto', $this->mode(4));
        self::assertSame(0, $this->revision());
    }

    public function testVaultRefsAreValidatedAndDescribedWithoutReadingSecrets(): void
    {
        $this->container['vaultSecrets'] = new class {
            public array $refs = [];
            public function available(): bool { return true; }
            public function describe(string $ref): object
            {
                $this->refs[] = $ref;
                return (object) ['ok' => false, 'reason' => 'not_shared'];
            }
        };
        $this->request('owner', 'POST', ['revision' => '0', 'owner_id' => '1', 'owners' => [1 => ['token_ref' => 'vault://17/password']]]);
        self::assertSame(422, $this->status);
        self::assertStringContainsString('vault://&lt;int&gt;/token', $this->html);
        self::assertStringNotContainsString('vault://17/password', $this->html);
        self::assertSame([], $this->container['vaultSecrets']->refs);

        $change = ['revision' => '0', 'owner_id' => '1', 'owners' => [1 => ['token_ref' => 'vault://17/token']]];
        $this->request('owner', 'POST', $change);
        self::assertSame(200, $this->status);
        self::assertStringContainsString('not_shared', $this->html);
        self::assertContains('vault://17/token', $this->container['vaultSecrets']->refs);
        self::assertSame(0, $this->revision());

        $this->request('save', 'POST', $change);
        self::assertSame(302, $this->status);
        self::assertSame('vault://17/token', $this->pdo->query('SELECT token_ref FROM gumshoe_owners WHERE id = 1')->fetchColumn());
    }

    public function testPinImportStagesBareNamesAndGithubUrlsAndReportsUnknown(): void
    {
        $this->request('importPins', 'POST', ['revision' => '0', 'pins' => "console\nhttps://github.com/symfony/symfony\nlaravel/framework"]);
        self::assertSame(200, $this->status);
        $xpath = $this->xpath();
        self::assertSame('pin', $xpath->evaluate('string(//input[@name="repos[1]"]/@value)'));
        self::assertSame('pin', $xpath->evaluate('string(//input[@name="repos[2]"]/@value)'));
        self::assertStringContainsString('Unknown repositories', $this->html);
        self::assertStringContainsString('laravel/framework', $this->html);
        self::assertSame('auto', $this->mode(2));
        self::assertSame(0, $this->revision());
    }

    public function testOverviewAndCoverageRenderWithContextualEscaping(): void
    {
        $this->pdo->exec('UPDATE gumshoe_settings SET project_id = '.$this->privateProject);
        $this->pdo->exec("INSERT INTO gumshoe_findings (group_id, ecosystem, package, priority) VALUES (1, 'Packagist', 'symfony/console', 'urgent')");
        $this->pdo->exec("INSERT INTO gumshoe_lockfiles (repo_id, path_hash, path, blob_sha, kind, status, parser_version)
            VALUES (1, 'hash', 'composer.lock', 'blob', 'composer', 'ok', 1)");
        $this->pdo->exec("INSERT INTO gumshoe_deps (lockfile_id, ecosystem, name, version, scope, egress)
            VALUES (1, 'Packagist', 'symfony/console', '1.0.0', 'prod', 'private'),
                   (1, 'Packagist', 'symfony/console', '1.0.0', 'prod', 'unqueryable')");
        $this->request('index');
        self::assertSame(200, $this->status);
        foreach (['2 of 3 watched', '0 pinned', '0 excluded', 'missing', 'Show owners needing a token',
            'Last run', 'Never', 'Next due', 'Waiting for Vault', '1 urgent', 'Quick settings', 'Scanning', 'Hourly', 'Findings board',
            'Watch window', 'Include forks', 'Include archived', 'Deny prefixes', 'Watching', 'Not watching', 'Pinned',
            'Excluded', 'partial', 'inaccessible', 'no_lockfile', '1 private', '1 unqueryable',
            'Gumshoe needs Vault 1.1.0 with Server sharing on.', 'pushed 0d ago', 'idle '] as $label) {
            self::assertStringContainsString($label, $this->html);
        }
        $xpath = $this->xpath();
        self::assertSame(0.0, $xpath->evaluate('count(//input[contains(@name,"token_ref")])'));
        self::assertStringContainsString('project_id='.$this->privateProject, $xpath->evaluate('string(//a[contains(.,"Open findings")]/@href)'));
        $row = '//tr[@data-repo]';
        self::assertStringContainsString('</script>"&\'', $xpath->evaluate('string(('.$row.')[3])'));
        self::assertSame('Watch mode for symfony/</script>"&\'', $xpath->evaluate('string(('.$row.')[3]//select/@aria-label)'));
        $json = $xpath->evaluate('string(('.$row.')[3]/@data-repo)');
        self::assertStringContainsString('\u003C/script\u003E\u0022\u0026\u0027', $json);
        self::assertSame('symfony/</script>"&\'', json_decode($json, true, flags: JSON_THROW_ON_ERROR)['name']);
        self::assertStringNotContainsString('symfony/</script>', $this->html);
        self::assertStringContainsString('Assets/js/gumshoe.js', $this->html);
        self::assertStringContainsString('Assets/css/gumshoe.css', $this->html);
    }

    public function testSourcesAssetsAreScopedAwayFromCoreSettings(): void
    {
        $this->request('application', params: ['controller' => 'ConfigController', 'plugin' => '']);
        self::assertSame(200, $this->status);
        self::assertStringContainsString('Gumshoe · Sources', $this->html);
        self::assertStringNotContainsString('Assets/js/gumshoe.js', $this->html);
        self::assertStringNotContainsString('Assets/css/gumshoe.css', $this->html);
    }

    private function request(string $action, string $method = 'GET', array $values = [], bool $csrf = true, array $params = []): void
    {
        $this->html = '';
        $this->status = 0;
        if ($csrf && $values !== []) {
            $values['csrf_token'] = $this->container['token']->getCSRFToken();
        }
        $this->container['request'] = new Request($this->container, [
            'REQUEST_METHOD' => $method, 'REQUEST_URI' => '/index.php', 'SCRIPT_NAME' => '/index.php',
        ], $params + ['plugin' => 'Gumshoe', 'controller' => 'SourcesController', 'action' => $action], $values);
        $this->container['router']->dispatch();
        if (!$this->container->offsetExists('gumshoeScanner')) {
            $plugin = new Plugin($this->container);
            $plugin->initialize();
            $this->container['dispatcher']->addListener('app.bootstrap', [$plugin, 'onStartup']);
        }

        // Start from an authenticated session and use the real router, application ACL and 403 handling.
        $runner = new class($this->container) extends Runner {
            protected function executeMiddleware(): void
            {
                $this->dispatcher->dispatch(new \Symfony\Contracts\EventDispatcher\Event(), 'app.bootstrap');
                (new ApplicationAuthorizationMiddleware($this->container))->execute();
            }
        };
        $runner->execute();
    }

    private function revision(): int
    {
        return (int) $this->pdo->query('SELECT revision FROM gumshoe_settings WHERE watch_id = 1')->fetchColumn();
    }

    private function mode(int $id): string
    {
        return $this->pdo->query('SELECT mode FROM gumshoe_repos WHERE id = '.$id)->fetchColumn();
    }

    private function xpath(): DOMXPath
    {
        $document = new DOMDocument();
        $document->loadHTML($this->html, LIBXML_NOERROR | LIBXML_NOWARNING);
        return new DOMXPath($document);
    }
}
