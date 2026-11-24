<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Secrets\VaultTokenSource;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeTransport;
use Kanboard\Plugin\Vault\Model\ServerSecrets;
use Kanboard\Plugin\Vault\Secrets\ServiceSecrets;
use Kanboard\Plugin\Vault\Test\Support\Fixtures;
use KanboardTests\units\Base;

require_once 'tests/units/Base.php';

/**
 * Where the Vault checkout the autoloader serves lives, and whether it carries the consumer API.
 * The consumer API came from Vault's feat/server-reader branch (merged into main for v1.1.0); a checkout without it
 * skips. GUMSHOE_REQUIRE_VAULT=1 turns every skip into a failure and also requires the checkout's HEAD to contain
 * feat/server-reader's commit.
 */
final class VaultCheckout
{
    public const BRANCH = 'feat/server-reader';

    public static function dir(): ?string
    {
        if (class_exists(\Kanboard\Plugin\Vault\Plugin::class)) {
            return dirname((new \ReflectionClass(\Kanboard\Plugin\Vault\Plugin::class))->getFileName());
        }
        $dir = realpath(getcwd().'/plugins/Vault');
        return $dir === false ? null : $dir;
    }

    public static function hasConsumerApi(): bool
    {
        $dir = self::dir();
        return $dir !== null
            && interface_exists(ServiceSecrets::class)
            && class_exists(ServerSecrets::class)
            && is_file($dir.'/Test/Support/ServerFixture.php');
    }

    public static function branch(): string
    {
        $dir = self::dir();
        if ($dir === null) {
            return '';
        }
        return trim((string) shell_exec('git -C '.escapeshellarg($dir).' rev-parse --abbrev-ref HEAD 2>/dev/null'));
    }

    public static function required(): bool
    {
        return getenv('GUMSHOE_REQUIRE_VAULT') === '1';
    }

    /**
     * The checkout's HEAD contains feat/server-reader's commit (main after the v1.1.0 merge, or the branch itself).
     * Without that ref in the repo, only a checkout on the branch itself qualifies.
     */
    public static function containsConsumerBranch(): bool
    {
        $dir = self::dir();
        if ($dir === null) {
            return false;
        }
        $git = 'git -C '.escapeshellarg($dir).' ';
        exec($git.'rev-parse --verify --quiet '.escapeshellarg(self::BRANCH.'^{commit}').' 2>/dev/null', $out, $missing);
        if ($missing !== 0) {
            return self::branch() === self::BRANCH;
        }
        exec($git.'merge-base --is-ancestor '.escapeshellarg(self::BRANCH).' HEAD 2>/dev/null', $out, $notAncestor);
        return $notAncestor === 0;
    }

    /** Why this run cannot exercise the real consumer API, or null when it can. */
    public static function problem(): ?string
    {
        if (!self::hasConsumerApi()) {
            return 'Vault consumer API (Secrets\ServiceSecrets, Model\ServerSecrets) is absent from '.(self::dir() ?? 'plugins/Vault');
        }
        if (self::required() && !self::containsConsumerBranch()) {
            return 'Vault checkout ("'.self::branch().'") does not contain '.self::BRANCH;
        }
        return null;
    }
}

// Vault's own Server fixture (migrated schema, enrolled users, Server key file, Server-shared entries and grants),
// loaded only when the checkout has it; otherwise an empty stand-in so this file still parses on Vault main.
if (VaultCheckout::hasConsumerApi()) {
    require_once VaultCheckout::dir().'/Test/Support/ServerFixture.php';

    trait VaultServerFixture
    {
        use \ServerFixture;
    }
} else {
    trait VaultServerFixture
    {
    }
}

final class VaultIntegrationTest extends Base
{
    use VaultServerFixture;

    private const TOKEN_STATUSES = ['ok', 'expiring', 'expired', 'unknown', 'missing', 'refused'];

    private bool $vaultReady = false;

    protected function setUp(): void
    {
        $problem = VaultCheckout::problem();
        if ($problem !== null) {
            if (VaultCheckout::required()) {
                self::fail('GUMSHOE_REQUIRE_VAULT=1: '.$problem);
            }
            self::markTestSkipped($problem);
        }
        parent::setUp();
        $this->setUpAgents();
        $this->setUpServer();
        $this->vaultReady = true;
    }

    protected function tearDown(): void
    {
        if ($this->vaultReady) {
            $this->tearDownServer();
            $this->tearDownVault();
            parent::tearDown();
        }
    }

    public function testServerSharedTokenReachesOnlyTheGithubAuthorizationHeader(): void
    {
        $token = 'ghp_'.bin2hex(random_bytes(18));
        $entry = $this->shareToken(['Gumshoe'], $token);
        $source = $this->tokenSource($entry);
        self::assertTrue($source->available());

        $seen = [];
        $transport = new FakeTransport([
            static function (array $headers) use ($token, &$seen): Response {
                $seen[] = isset($headers['Authorization']) && hash_equals('Bearer '.$token, $headers['Authorization']);
                return new Response(200, [], '{}');
            },
        ]);
        $client = new Client($transport, 'https://kb.example/', $source);
        $client->send(new Request('gh.repo', 'https://api.github.com/repos/symfony/yaml', 'symfony'), 'gumshoe:integration');
        $client->send(new Request('kev', 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json'));

        self::assertSame([true], $seen, 'the Vault value is the GitHub hop\'s bearer token');
        self::assertSame([true, false], $transport->authenticated, 'a non-GitHub hop carries no Authorization header');
        self::assertSame('unknown', $source->status('symfony')['status'], 'no expiry header yet');

        $reads = $this->auditRows('server_read');
        self::assertCount(1, $reads, 'one Vault read per owner per slice');
        self::assertSame(['Gumshoe', 'gumshoe:integration', (string) $entry],
            [$reads[0]['consumer'], $reads[0]['job_ref'], (string) $reads[0]['object_id']]);
        self::assertFalse(str_contains(json_encode($this->auditRows()), $token), 'the value is not in Vault\'s audit log');
        $source->endSlice();
    }

    public function testGrantWithoutGumshoeIsRefusedAndNoRequestIsSent(): void
    {
        $entry = $this->shareToken(['CveHunter'], 'ghp_'.bin2hex(random_bytes(18)));
        $source = $this->tokenSource($entry);
        self::assertTrue($source->available());

        $transport = new FakeTransport();
        $client = new Client($transport, 'https://kb.example/', $source);
        try {
            $client->send(new Request('gh.repo', 'https://api.github.com/repos/symfony/yaml', 'symfony'), 'gumshoe:integration');
            self::fail('a refused token must not reach the transport');
        } catch (HttpFailure $failure) {
            self::assertSame('token_unavailable', $failure->reason);
        }
        self::assertSame([], $transport->requests);

        $status = $source->status('symfony')['status'];
        self::assertSame('refused:consumer_not_allowed', $status);
        // ScanSlice stores the frozen status: the part before the reason.
        self::assertContains(strtok($status, ':'), self::TOKEN_STATUSES);
        self::assertSame('refused', strtok($status, ':'));
        self::assertCount(1, $this->auditRows('server_read_denied'));
        self::assertSame([], $this->auditRows('server_read'));
    }

    /** A Server-shared entry of alice's holding $token in the custom field `token`, granted to $consumers. */
    private function shareToken(array $consumers, #[\SensitiveParameter] string $token): int
    {
        $payload = Fixtures::fullEntry();
        $payload['fields'][] = ['name' => 'token', 'value' => $token, 'protected' => true];
        $entry = $this->serverShare($consumers, ['token'], $payload);
        unset($this->container['vaultSecrets']);
        $this->container['vaultSecrets'] = fn (): ServerSecrets => $this->serverSecrets();
        return $entry;
    }

    private function tokenSource(int $entry): VaultTokenSource
    {
        return new VaultTokenSource(
            $this->container,
            static fn (string $owner): ?string => $owner === 'symfony' ? 'vault://'.$entry.'/token' : null,
        );
    }
}
