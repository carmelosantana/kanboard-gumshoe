<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\CurlTransport;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Secrets\VaultTokenSource;
use Kanboard\Plugin\Gumshoe\Test\Fakes\FakeVaultSecrets;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use PHPUnit\Framework\TestCase;

final class CurlTransportTest extends TestCase
{
    public function testUsesGuardedOptionsAndFreshHeadersOnRedirect(): void
    {
        $adapter = new RecordingCurlAdapter([
            static function ($handle, #[\SensitiveParameter] array $options): int {
                self::assertContains('Authorization: Bearer ghp_FAKE_DO_NOT_LEAK', $options[CURLOPT_HTTPHEADER]);
                self::assertFalse($options[CURLOPT_FOLLOWLOCATION]);
                self::assertSame(CURLPROTO_HTTPS, $options[CURLOPT_PROTOCOLS]);
                self::assertSame(CURLPROTO_HTTPS, $options[CURLOPT_REDIR_PROTOCOLS]);
                self::assertSame(20, $options[CURLOPT_TIMEOUT]);
                self::assertSame(5, $options[CURLOPT_CONNECTTIMEOUT]);
                self::assertSame('', $options[CURLOPT_PROXY]);
                self::assertSame('*', $options[CURLOPT_NOPROXY]);
                ($options[CURLOPT_HEADERFUNCTION])($handle, "HTTP/1.1 200 Connection established\r\n");
                ($options[CURLOPT_HEADERFUNCTION])($handle, "X-Proxy: discarded\r\n");
                ($options[CURLOPT_HEADERFUNCTION])($handle, "HTTP/2 302\r\n");
                ($options[CURLOPT_HEADERFUNCTION])($handle, "Location: https://objects.githubusercontent.com/fixture\r\n");
                return 302;
            },
            static function ($handle, array $options): int {
                self::assertFalse(str_contains(implode(' ', $options[CURLOPT_HTTPHEADER]), 'Authorization:'));
                self::assertSame('https://objects.githubusercontent.com/fixture', $options[CURLOPT_URL]);
                ($options[CURLOPT_HEADERFUNCTION])($handle, "HTTP/2 200\r\n");
                ($options[CURLOPT_WRITEFUNCTION])($handle, 'public fixture');
                return 200;
            },
        ]);
        $client = $this->client($adapter, 'ghp_FAKE_DO_NOT_LEAK');
        $response = $client->send(new Request('gh.blob', 'https://api.github.com/repos/symfony/yaml/git/blobs/abc', 'symfony'));
        self::assertSame(200, $response->status);
        self::assertSame('public fixture', $response->body);
        self::assertNull($response->header('x-proxy'));
        self::assertSame([], $adapter->options);
        self::assertSame(2, $adapter->resets);
    }

    public function testEnforcesDecodedAndWireCapsThroughCallbacksAndFinalByteCount(): void
    {
        $decoded = 10 * 1024 * 1024;
        $wire = 14 * 1024 * 1024;
        foreach (['decoded_too_large', 'wire_too_large', 'final_wire'] as $case) {
            $adapter = new RecordingCurlAdapter([
                static function ($handle, array $options) use ($case, $decoded, $wire): int {
                    self::assertSame('http://proxy.example:8080', $options[CURLOPT_PROXY]);
                    self::assertSame('', $options[CURLOPT_NOPROXY]);
                    $progress = $options[CURLOPT_XFERINFOFUNCTION];
                    self::assertSame(0, $progress($handle, $wire, $wire, 0, 0));
                    if ($case === 'decoded_too_large') {
                        $write = $options[CURLOPT_WRITEFUNCTION];
                        self::assertSame($decoded, $write($handle, str_repeat('x', $decoded)));
                        self::assertSame(0, $write($handle, 'x'));
                    } elseif ($case === 'wire_too_large') {
                        self::assertSame(1, $progress($handle, 0, $wire + 1, 0, 0));
                    }
                    return 200;
                },
            ]);
            $adapter->wireBytes = $case === 'final_wire' ? $wire + 1 : 0;
            try {
                $this->client($adapter, 'ghp_FAKE_DO_NOT_LEAK', 'http://proxy.example:8080')
                    ->send(new Request('gh.repo', 'https://api.github.com/repos/symfony/yaml', 'symfony'));
                self::fail('Accepted an oversized download');
            } catch (HttpFailure $failure) {
                self::assertSame($case === 'final_wire' ? 'wire_too_large' : $case, $failure->reason);
            }
            self::assertSame([], $adapter->options);
        }
    }

    public function testSecretsStayOutOfTraceResponsesAndRetainedCurlOptions(): void
    {
        $old = ini_set('zend.exception_ignore_args', '0');
        try {
            foreach (['ghp_FAKE_DO_NOT_LEAK', 'github_pat_FAKE_DO_NOT_LEAK'] as $token) {
                $adapter = new RecordingCurlAdapter([
                    static function ($handle, #[\SensitiveParameter] array $options): int {
                        $authorization = $options[CURLOPT_HTTPHEADER][array_key_last($options[CURLOPT_HTTPHEADER])];
                        throw new \TypeError($authorization);
                    },
                    static function ($handle, #[\SensitiveParameter] array $options): int {
                        $authorization = $options[CURLOPT_HTTPHEADER][array_key_last($options[CURLOPT_HTTPHEADER])];
                        self::assertTrue(str_starts_with($authorization, 'Authorization: Bearer '));
                        ($options[CURLOPT_HEADERFUNCTION])($handle, "X-Echo: $authorization\r\n");
                        ($options[CURLOPT_WRITEFUNCTION])($handle, $authorization);
                        return 200;
                    },
                ]);
                $request = new Request('gh.repo', 'https://api.github.com/repos/symfony/yaml', 'symfony');
                $client = $this->client($adapter, $token);
                try {
                    $client->send($request);
                    self::fail('Adapter failure was swallowed');
                } catch (HttpFailure $failure) {
                    self::assertSame('transport_error', $failure->reason);
                    self::assertSame('gh.repo', $failure->operation);
                    self::assertSame('api.github.com', $failure->host);
                    self::assertNull($failure->status);
                    self::assertNull($failure->getPrevious());
                    self::assertStringNotContainsString($token, $failure->getMessage());
                    self::assertStringNotContainsString($token, print_r($failure->getTrace(), true));
                }
                self::assertSame([], $adapter->options);
                $response = $client->send($request);
                self::assertStringNotContainsString($token, var_export($response, true));
                self::assertStringNotContainsString($token, json_encode($response, JSON_THROW_ON_ERROR));
                self::assertSame('Authorization: Bearer [redacted]', $response->body);
                self::assertSame([], $adapter->options);
            }
        } finally {
            ini_set('zend.exception_ignore_args', $old);
        }
    }

    private function client(RecordingCurlAdapter $adapter, #[\SensitiveParameter] string $token, ?string $proxy = null): Client
    {
        $vault = new FakeVaultSecrets(static fn () => SecretValue::of($token));
        $source = new VaultTokenSource(['vaultSecrets' => $vault], static fn () => 'vault://17/token');
        return new Client(new CurlTransport($proxy, $adapter), 'https://kanboard.example/', $source);
    }
}

final class RecordingCurlAdapter
{
    public array $options = [];
    public int $resets = 0;
    public int $wireBytes = 0;
    private int $status = 0;

    public function __construct(private array $calls)
    {
    }

    public function __invoke(string $function, #[\SensitiveParameter] mixed ...$args): mixed
    {
        switch ($function) {
            case 'curl_init':
                return new \stdClass();
            case 'curl_setopt_array':
                $this->options = $args[1];
                return true;
            case 'curl_exec':
                $this->status = array_shift($this->calls)($args[0], $this->options);
                return true;
            case 'curl_getinfo':
                return $args[1] === CURLINFO_RESPONSE_CODE ? $this->status : $this->wireBytes;
            case 'curl_reset':
                $this->options = [];
                $this->resets++;
                return null;
        }
        throw new \LogicException('Unexpected cURL adapter call');
    }
}
