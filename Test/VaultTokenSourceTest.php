<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Secrets\VaultTokenSource;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeVaultSecrets;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use PHPUnit\Framework\TestCase;
use Pimple\Container;

final class VaultTokenSourceTest extends TestCase
{
    public function testAvailabilityIsLazyAndInvalidRefsNeverReachVault(): void
    {
        $container = new Container();
        $source = new VaultTokenSource($container, static fn ($owner) => $owner);
        self::assertFalse($source->available());
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of('ghp_FAKE_DO_NOT_LEAK'));
        $container['vaultSecrets'] = $vault;
        self::assertTrue($source->available());
        foreach (['vault://0/token', 'vault://01/token', 'vault://1234567890123456789/token', 'vault://17/password', 'vault://17/token?x=y'] as $ref) {
            $source = new VaultTokenSource($container, static fn () => $ref);
            self::assertNull($source->forOwner('symfony', 'fixture'));
            self::assertSame('refused:invalid_ref', $source->status('symfony')['status']);
        }
        self::assertSame([], $vault->reads);
        $vault->ready = false;
        self::assertFalse($source->available());
    }

    public function testReadsOncePerOwnerForFortyRequestsAndDropsValueAtSliceEnd(): void
    {
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of('ghp_FAKE_DO_NOT_LEAK'));
        $source = new VaultTokenSource(['vaultSecrets' => $vault], static fn ($owner) => $owner === 'symfony' ? 'vault://17/token' : 'vault://18/token');
        $transport = new FakeTransport();
        $client = new Client($transport, 'https://kanboard.example/', $source);
        for ($i = 0; $i < 40; $i++) {
            $client->send(new Request('gh.repo', 'https://api.github.com/repos/symfony/yaml', 'Symfony'), 'slice-1');
        }
        self::assertSame([['Gumshoe', 'vault://17/token', 'slice-1']], $vault->reads);
        self::assertSame(array_fill(0, 40, true), $transport->authenticated);
        $previous = $vault->lastValue;
        self::assertInstanceOf(SecretValue::class, $previous->get());
        $source->forOwner('php', 'slice-1');
        self::assertSame(['Gumshoe', 'vault://18/token', 'slice-1'], $vault->reads[1]);
        $source->endSlice();
        self::assertNull($previous->get());
        self::assertNull($vault->lastValue->get());
        $source->forOwner('symfony', 'slice-2');
        self::assertSame(['Gumshoe', 'vault://17/token', 'slice-2'], $vault->reads[2]);
    }

    public function testRefusalIsCachedAndRateLimitBackoffSurvivesSlice(): void
    {
        $now = 1000;
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of('github_pat_FAKE_DO_NOT_LEAK'));
        $source = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token', static function () use (&$now): int {
            return $now;
        });
        foreach (['not_shared', 'rate_limited'] as $reason) {
            $vault->refusal = $reason;
            self::assertNull($source->forOwner('symfony'));
            self::assertNull($source->forOwner('symfony'));
            self::assertSame('refused:'.$reason, $source->status('symfony')['status']);
            $source->endSlice();
        }
        self::assertSame(1060, $source->status('symfony')['retryAt']);
        $vault->refusal = null;
        self::assertNull($source->forOwner('symfony'));
        self::assertCount(2, $vault->reads);
        $now = 1060;
        self::assertInstanceOf(SecretValue::class, $source->forOwner('symfony'));
        self::assertCount(3, $vault->reads);
    }

    public function testExpiryFromAuthenticatedGithubResponses(): void
    {
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of('ghp_FAKE_DO_NOT_LEAK'));
        $source = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token');
        $now = strtotime('2026-11-24 UTC');
        $client = new Client(new FakeTransport([
            new Response(200),
            new Response(200, ['github-authentication-token-expiration' => '2026-12-31 00:00:00 UTC']),
            new Response(200, ['github-authentication-token-expiration' => '2026-12-08 00:00:00 UTC']),
            new Response(401),
        ]), 'https://kanboard.example/', $source, static fn () => $now);
        $request = new Request('gh.list', 'https://api.github.com/user/repos', 'symfony');
        foreach (['unknown', 'ok', 'expiring', 'expired'] as $expected) {
            $client->send($request);
            self::assertSame($expected, $source->status('symfony')['status']);
        }
    }

    public function testMissingExpiryHeaderPreservesStateAcrossRequestsAndSlices(): void
    {
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of('ghp_FAKE_DO_NOT_LEAK'));
        $source = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token');
        $now = strtotime('2026-11-24 UTC');
        $expiry = '2026-12-08 00:00:00 UTC';
        $client = new Client(new FakeTransport([
            new Response(200, ['github-authentication-token-expiration' => $expiry]),
            new Response(403),
            new Response(404),
            new Response(401),
        ]), 'https://kanboard.example/', $source, static fn () => $now);
        $request = new Request('gh.list', 'https://api.github.com/user/repos', 'symfony');
        $state = ['status' => 'expiring', 'expiresAt' => strtotime($expiry), 'retryAt' => null];
        $client->send($request);
        self::assertSame($state, $source->status('symfony'));
        $client->send($request);
        self::assertSame($state, $source->status('symfony'));
        $source->endSlice();
        self::assertInstanceOf(SecretValue::class, $source->forOwner('symfony'));
        self::assertSame($state, $source->status('symfony'));
        $client->send($request);
        self::assertSame($state, $source->status('symfony'));
        $client->send($request);
        $state['status'] = 'expired';
        self::assertSame($state, $source->status('symfony'));
    }
}
