<?php

namespace Kanboard\Plugin\Gumshoe\Secrets;

use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Vault\Secrets\SecretValue;
use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;

final class VaultTokenSource implements TokenSource
{
    /** @var array<string, SecretValue|null> */
    private array $slice = [];
    private array $states = [];
    private readonly \Closure $clock;

    /** $refForOwner receives a lowercase GitHub login and returns its configured Vault ref. */
    public function __construct(
        private readonly array|\ArrayAccess $container,
        private readonly \Closure $refForOwner,
        ?\Closure $clock = null,
    ) {
        $this->clock = $clock ?? time(...);
    }

    public function available(): bool
    {
        try {
            return isset($this->container['vaultSecrets']) && $this->container['vaultSecrets']->available();
        } catch (\Throwable) {
            return false;
        }
    }

    public function forOwner(string $owner, ?string $jobRef = null): ?SecretValue
    {
        $owner = strtolower($owner);
        if (array_key_exists($owner, $this->slice)) {
            return $this->slice[$owner];
        }
        $now = ($this->clock)();
        if (($this->states[$owner]['retryAt'] ?? 0) > $now) {
            return null;
        }

        $this->slice[$owner] = null;
        try {
            $ref = ($this->refForOwner)($owner);
            if ($ref === null || $ref === '') {
                $this->setStatus($owner, 'missing');
            } elseif (!is_string($ref) || preg_match('~\Avault://[1-9][0-9]{0,17}/token\z~', $ref) !== 1) {
                $this->setStatus($owner, 'refused:invalid_ref');
            } elseif (!$this->available()) {
                $this->setStatus($owner, 'refused:server_off');
            } else {
                $this->slice[$owner] = $this->container['vaultSecrets']->read('Gumshoe', $ref, $jobRef);
                if (!in_array($this->status($owner)['status'], ['ok', 'expiring', 'expired'], true)) {
                    $this->setStatus($owner, 'unknown');
                }
            }
        } catch (ServiceSecretException $refusal) {
            $reason = $refusal->reason();
            $this->setStatus($owner, 'refused:'.$reason, retryAt: $reason === 'rate_limited' ? $now + 60 : null);
        } catch (\Throwable) {
            $this->setStatus($owner, 'refused:unavailable');
        }
        return $this->slice[$owner];
    }

    public function status(string $owner): array
    {
        return $this->states[strtolower($owner)] ?? ['status' => 'unknown', 'expiresAt' => null, 'retryAt' => null];
    }

    public function observeGithub(string $owner, #[\SensitiveParameter] Response $response, int $now): void
    {
        $owner = strtolower($owner);
        $header = $response->header('github-authentication-token-expiration');
        if ($header === null) {
            if ($response->status === 401) {
                $this->setStatus($owner, 'expired', $this->status($owner)['expiresAt']);
            }
            return;
        }
        $expiresAt = null;
        if (preg_match('/\A\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} (?:UTC|[+-]\d{4})\z/', $header) === 1) {
            $expiresAt = strtotime($header) ?: null;
        }

        $status = match (true) {
            $response->status === 401, $expiresAt !== null && $expiresAt <= $now => 'expired',
            $expiresAt === null => 'unknown',
            $expiresAt <= $now + 14 * 86400 => 'expiring',
            default => 'ok',
        };
        $this->setStatus($owner, $status, $expiresAt);
    }

    public function endSlice(): void
    {
        $this->slice = [];
    }

    private function setStatus(string $owner, string $status, ?int $expiresAt = null, ?int $retryAt = null): void
    {
        $this->states[$owner] = compact('status', 'expiresAt', 'retryAt');
    }
}
