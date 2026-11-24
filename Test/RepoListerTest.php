<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\GitHub\RepoLister;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Model\RepoModel;
use Kanboard\Plugin\Gumshoe\Secrets\VaultTokenSource;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeVaultSecrets;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use KanboardTests\units\Base;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/bootstrap.php';
require_once __DIR__.'/ReleasesConnection.php';
require_once __DIR__.'/Fakes/FakeVaultSecrets.php';

final class RepoListerTest extends Base
{
    use ReleasesConnection;

    private const API = 'https://api.github.com';

    public function testUserListingFiltersTheOwnerAndFollowsValidatedNumericPagination(): void
    {
        $next = self::API.'/user/17/repos?affiliation=owner&page=2';
        [$lister, $transport, $vault] = $this->lister([
            $this->page([$this->repo(1, 'CarmeloSantana', 'ai-context-builder'), $this->repo(2, 'symfony', 'yaml')], $next),
            $this->page([$this->repo(3, 'carmelosantana', 'kanboard-mcp')]),
        ]);
        $listing = $lister->list(['login' => 'carmelosantana', 'kind' => 'user'], 'inventory');
        self::assertSame('complete', $listing['status']);
        self::assertSame(['ai-context-builder', 'kanboard-mcp'], array_column($listing['repos'], 'name'));
        self::assertSame([self::API.'/user/repos?affiliation=owner', $next], array_column($transport->requests, 'url'));
        self::assertSame([true, true], $transport->authenticated);
        self::assertSame([['Gumshoe', 'vault://17/token', 'inventory']], $vault->reads);
    }

    public function testOnlyCompleteOrgListingMarksMissingReposAndKeepsModeOnRename(): void
    {
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $pdo = $this->container['db']->getConnection();
        version_1($pdo);
        $pdo->exec("INSERT INTO gumshoe_owners (login, kind) VALUES ('symfony', 'org')");
        $repos = new RepoModel($pdo);
        $owner = ['login' => 'symfony', 'kind' => 'org'];
        $first = $this->repo(4294967297, 'symfony', 'yaml');
        $second = $this->repo(4294967298, 'symfony', 'console');
        $next = self::API.'/organizations/17/repos?type=all&page=2';
        [$lister, $transport] = $this->lister([
            $this->page([$first, $second]),
            $this->page([$first], $next),
            new Response(403, ['Retry-After' => '60']),
            $this->page([array_replace($first, ['name' => 'Yaml'])]),
            $this->page([]),
            $this->page([$second]),
        ]);

        $repos->applyListing(1, $lister->list($owner), 10);
        $id = (int) $pdo->query("SELECT id FROM gumshoe_repos WHERE name = 'yaml'")->fetchColumn();
        $pdo->exec("UPDATE gumshoe_repos SET mode = 'pin' WHERE id = ".$id);
        $before = $repos->forOwner(1);

        $partial = $lister->list($owner);
        self::assertSame('incomplete', $partial['status']);
        self::assertSame(1_800_000_060, $partial['retryAt']);
        $repos->applyListing(1, $partial, 20);
        self::assertSame($before, $repos->forOwner(1));
        self::assertSame([self::API.'/orgs/symfony/repos?type=all', self::API.'/orgs/symfony/repos?type=all', $next],
            array_column($transport->requests, 'url'));

        $repos->applyListing(1, $lister->list($owner), 30);
        $rows = array_column($repos->forOwner(1), null, 'name');
        self::assertSame($id, (int) $rows['Yaml']['id']);
        self::assertSame('pin', $rows['Yaml']['mode']);
        self::assertNull($rows['Yaml']['gone_at']);
        self::assertSame(30, (int) $rows['console']['gone_at']);

        $repos->applyListing(1, $lister->list($owner), 40);
        $repos->applyListing(1, $lister->list($owner), 50);
        $rows = array_column($repos->forOwner(1), null, 'name');
        self::assertNull($rows['console']['gone_at']);
        self::assertSame(40, (int) $rows['Yaml']['gone_at']);
    }

    public function testMalformedPageAndRejectedPaginationAreIncomplete(): void
    {
        $first = $this->repo(1, 'symfony', 'yaml');
        foreach ([
            new Response(200, [], '{}'),
            $this->page([['id' => 1]]),
            $this->page([array_replace($first, ['pushed_at' => "2026-11-23T12:00:00Z\0"])]),
            $this->page([$first], 'https://api.github.com/orgs/octokit/repos?page=2'),
            $this->page([$first], self::API.'/orgs/symfony/repos?type=all'),
        ] as $response) {
            [$lister, $transport] = $this->lister([$response]);
            $listing = $lister->list(['login' => 'symfony', 'kind' => 'org']);
            self::assertSame('incomplete', $listing['status']);
            self::assertSame([], $listing['repos']);
            self::assertCount(1, $transport->requests);
        }
    }

    public function testACompleteListingCanReuseANameFreedByARenameOnTheSamePage(): void
    {
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $pdo = $this->container['db']->getConnection();
        version_1($pdo);
        $pdo->exec("INSERT INTO gumshoe_owners (login, kind) VALUES ('symfony', 'org')");
        $repos = new RepoModel($pdo);
        $owner = ['login' => 'symfony', 'kind' => 'org'];
        [$lister] = $this->lister([
            $this->page([$this->repo(1, 'symfony', 'yaml')]),
            $this->page([$this->repo(2, 'symfony', 'yaml'), $this->repo(1, 'symfony', 'console')]),
        ]);

        $repos->applyListing(1, $lister->list($owner), 10);
        $pdo->exec("UPDATE gumshoe_repos SET mode = 'pin' WHERE github_id = 1");
        $repos->applyListing(1, $lister->list($owner), 20);
        $rows = array_column($repos->forOwner(1), null, 'github_id');
        self::assertSame('console', $rows[1]['name']);
        self::assertSame('pin', $rows[1]['mode']);
        self::assertSame('yaml', $rows[2]['name']);
        self::assertSame('auto', $rows[2]['mode']);
    }

    public function testOnlyACompleteListingCanReassignAMissingReposName(): void
    {
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $pdo = $this->container['db']->getConnection();
        version_1($pdo);
        $pdo->exec("INSERT INTO gumshoe_owners (login, kind) VALUES ('symfony', 'org')");
        $repos = new RepoModel($pdo);
        $owner = ['login' => 'symfony', 'kind' => 'org'];
        $replacement = $this->repo(2, 'symfony', 'yaml');
        [$lister] = $this->lister([
            $this->page([$this->repo(1, 'symfony', 'yaml')]),
            $this->page([$replacement], self::API.'/organizations/17/repos?type=all&page=2'),
            new Response(503),
            $this->page([$replacement]),
        ]);

        $repos->applyListing(1, $lister->list($owner), 10);
        $pdo->exec("UPDATE gumshoe_repos SET mode = 'pin' WHERE github_id = 1");
        $before = $repos->forOwner(1);
        $repos->applyListing(1, $lister->list($owner), 20);
        self::assertSame($before, $repos->forOwner(1));

        $repos->applyListing(1, $lister->list($owner), 30);
        $rows = array_column($repos->forOwner(1), null, 'github_id');
        self::assertCount(2, $rows);
        self::assertSame($before[0]['id'], $rows[1]['id']);
        self::assertSame('pin', $rows[1]['mode']);
        self::assertSame(30, (int) $rows[1]['gone_at']);
        self::assertSame('yaml', $rows[2]['name']);
        self::assertSame('auto', $rows[2]['mode']);
        self::assertNull($rows[2]['gone_at']);
    }

    private function lister(array $responses): array
    {
        $transport = new FakeTransport($responses);
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of(bin2hex(random_bytes(16))));
        $tokens = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token');
        return [new RepoLister(new Client($transport, 'https://kanboard.example/', $tokens, static fn () => 1_800_000_000)), $transport, $vault];
    }

    private function repo(int $id, string $owner, string $name): array
    {
        return [
            'id' => $id, 'owner' => ['login' => $owner, 'id' => 17], 'name' => $name,
            'private' => false, 'archived' => false, 'fork' => false,
            'pushed_at' => '2026-11-23T12:00:00Z', 'default_branch' => 'main',
        ];
    }

    private function page(array $repos, ?string $next = null): Response
    {
        return new Response(200, $next === null ? [] : ['Link' => '<'.$next.'>; rel="next"'], json_encode($repos, JSON_THROW_ON_ERROR));
    }
}
