<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Secrets\Redactor;
use Kanboard\Plugin\Gumshoe\Secrets\VaultTokenSource;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeVaultSecrets;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use PHPUnit\Framework\TestCase;

final class HttpClientTest extends TestCase
{
    public function testRejectsAuthoritiesBeforeSendingAndCanonicalisesValidOnes(): void
    {
        $transport = new FakeTransport();
        $client = new Client($transport, 'https://kanboard.example/');
        foreach ([
            'http://api.github.com', 'https://api.github.com:444', 'https://user@api.github.com',
            'https://@api.github.com', 'https://api.github.com.evil.example', 'https://api.github.com.',
            'https://api.github.com\\@example.org', '//api.github.com', "https://api.github.com\n",
            'https://raw.githubusercontent.com',
        ] as $authority) {
            try {
                $client->send(new Request('gh.list', $authority.'/user/repos'));
                self::fail('Invalid authority reached send');
            } catch (HttpFailure $failure) {
                self::assertSame('host_not_allowed', $failure->reason);
                self::assertSame([], $transport->requests);
            }
        }
        $client->send(new Request('gh.list', 'HTTPS://API.GITHUB.COM:443/user/repos?page=2'));
        self::assertSame('https://api.github.com/user/repos?page=2', $transport->requests[0]->url);
    }

    public function testPaginationKeepsEndpointAndPreservesRequest(): void
    {
        $transport = new FakeTransport();
        $client = new Client($transport, 'https://kanboard.example/');
        $request = new Request('gh.list', 'https://api.github.com/orgs/symfony/repos?type=all', 'symfony');
        $response = new Response(200, ['Link' => '<https://API.GITHUB.COM:443/orgs/symfony/repos?page=2>; rel="next", <https://api.github.com/orgs/symfony/repos?page=5>; rel="last"']);
        $next = $client->nextPage($request, $response);
        self::assertSame('https://api.github.com/orgs/symfony/repos?page=2', $next->url);
        self::assertSame('symfony', $next->owner);
        self::assertNull($client->nextPage($request, new Response(200)));
        foreach ([
            'https://api.osv.dev/orgs/symfony/repos',
            'https://api.github.com/orgs/symfony/repos-extra',
            'https://api.github.com/orgs/symfony/repos/%2e%2e',
            'https://api.github.com/orgs/php/repos',
            'https://api.github.com:8080/orgs/symfony/repos',
        ] as $target) {
            try {
                $client->nextPage($request, new Response(200, ['Link' => '<'.$target.'>; rel="next"']));
                self::fail('Invalid pagination target accepted');
            } catch (HttpFailure $failure) {
                self::assertContains($failure->reason, ['host_not_allowed', 'pagination_not_allowed']);
            }
        }
        self::assertSame([], $transport->requests);
    }

    public function testAuthorizesOneOwnerAndUsesFreshHeadersForBlobRedirect(): void
    {
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of('ghp_FAKE_DO_NOT_LEAK'));
        $tokens = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token');
        $transport = new FakeTransport([
            static function (#[\SensitiveParameter] array $headers): Response {
                self::assertTrue(($headers['Authorization'] ?? '') === 'Bearer ghp_FAKE_DO_NOT_LEAK');
                self::assertSame('Kanboard-Gumshoe/1.0.0 (+https://kanboard.example/)', $headers['User-Agent']);
                return new Response(302, [
                    'Location' => 'https://objects.githubusercontent.com/public-fixture',
                    'github-authentication-token-expiration' => '2026-12-31 00:00:00 UTC',
                ]);
            },
            new Response(200, [], 'public fixture'),
        ]);
        $client = new Client($transport, 'https://kanboard.example/', $tokens, static fn () => strtotime('2026-12-25 UTC'));
        $blob = new Request('gh.blob', 'https://api.github.com/repos/symfony/yaml/git/blobs/abc', 'Symfony');
        self::assertSame('public fixture', $client->send($blob)->body);
        self::assertSame('expiring', $tokens->status('symfony')['status']);
        self::assertSame('https://objects.githubusercontent.com/public-fixture', $transport->requests[1]->url);
        $client->send(new Request('osv.query', 'https://api.osv.dev/v1/query', 'symfony', 'POST', '{}'));
        $client->send(new Request('kev', 'https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json', 'symfony'));
        $client->send(new Request('gh.advisories', 'https://api.github.com/advisories'));
        self::assertSame([true, false, false, false, false], $transport->authenticated);
        self::assertSame([['Gumshoe', 'vault://17/token', null]], $vault->reads);

        try {
            $client->send(new Request('gh.repo', 'https://api.github.com/repos/php/php-src', 'symfony'));
            self::fail('Used a token for a different owner');
        } catch (HttpFailure $failure) {
            self::assertSame('owner_not_allowed', $failure->reason);
        }
        self::assertCount(5, $transport->requests);
    }

    public function testBlocksCallerCredentialsAndUnboundAuthenticatedListings(): void
    {
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of('ghp_FAKE_DO_NOT_LEAK'));
        $tokens = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token');
        $transport = new FakeTransport();
        $client = new Client($transport, 'https://kanboard.example/', $tokens);

        foreach ([
            [new Request('osv.query', 'https://api.osv.dev/v1/query', headers: ['authorization' => 'Bearer fixture']), 'header_not_allowed'],
            [new Request('gh.list', 'https://api.github.com/user/123/repos', 'symfony'), 'owner_not_allowed'],
        ] as [$request, $reason]) {
            try {
                $client->send($request);
                self::fail('Sent an unauthorized request');
            } catch (HttpFailure $failure) {
                self::assertSame($reason, $failure->reason);
            }
        }
        self::assertSame([], $vault->reads);
        self::assertSame([], $transport->requests);
    }

    public function testRejectsOtherRedirectsAndLimitsBlobToOneHop(): void
    {
        $repo = new Request('gh.repo', 'https://api.github.com/repos/symfony/yaml');
        $blob = new Request('gh.blob', 'https://api.github.com/repos/symfony/yaml/git/blobs/abc');
        foreach ([
            [$repo, 'https://objects.githubusercontent.com/fixture', 1],
            [$blob, 'https://githubusercontent.com/fixture', 1],
            [$blob, 'https://objects.githubusercontent.com.example/fixture', 1],
            [$blob, 'https://objects.githubusercontent.com/fixture', 2],
        ] as [$request, $target, $calls]) {
            $redirect = new Response(302, ['location' => $target]);
            $transport = new FakeTransport([$redirect, $redirect]);
            try {
                (new Client($transport, 'https://kanboard.example/'))->send($request);
                self::fail('Invalid redirect followed');
            } catch (HttpFailure $failure) {
                self::assertContains($failure->reason, ['host_not_allowed', 'redirect_not_allowed']);
            }
            self::assertCount($calls, $transport->requests);
        }
    }

    public function testRetryAfterPrimaryLimitAndCappedSecondaryLimit(): void
    {
        $secondary = new Response(403, [], file_get_contents(__DIR__.'/fixtures/github/error-403-secondary.json'));
        $responses = [
            new Response(503, ['Retry-After' => '25']),
            new Response(429, ['Retry-After' => gmdate(DATE_RFC7231, 1040)]),
            new Response(403, ['x-ratelimit-remaining' => '0', 'x-ratelimit-reset' => '1075']),
            new Response(403, [], '{"message":"Resource not accessible"}'),
            ...array_fill(0, 6, $secondary),
            new Response(200),
            $secondary,
        ];
        $client = new Client(new FakeTransport($responses), 'https://kanboard.example/', clock: static fn () => 1000);
        $request = new Request('gh.list', 'https://api.github.com/user/repos');
        foreach ([1025, 1040, 1075, null, 1060, 1120, 1240, 1480, 1900, 1900, null, 1060] as $expected) {
            self::assertSame($expected, $client->send($request)->retryAt);
        }
    }

    public function testRedactorStripsClassicAndFineGrainedPatterns(): void
    {
        foreach (['ghp_'.str_repeat('A', 20), 'github_pat_'.str_repeat('A_', 10)] as $value) {
            self::assertSame('before [redacted] after', Redactor::redact("before $value after"));
        }
    }
}
