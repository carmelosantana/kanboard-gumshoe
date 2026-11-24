<?php

namespace Kanboard\Plugin\Vault\Secrets {
    // Keep the unit suite runnable in a standalone Gumshoe checkout.
    if (!class_exists(SecretValue::class)) {
        final class SecretValue
        {
            private static ?\WeakMap $values = null;

            public static function of(#[\SensitiveParameter] string $value): self
            {
                $secret = new self();
                self::$values ??= new \WeakMap();
                self::$values[$secret] = $value;
                return $secret;
            }

            public function reveal(): string
            {
                return self::$values[$this];
            }
        }
    }

    if (!class_exists(ServiceSecretException::class)) {
        final class ServiceSecretException extends \RuntimeException
        {
            public const REASONS = ['rate_limited', 'not_shared'];

            public function reason(): string
            {
                return $this->getMessage();
            }
        }
    }
}

namespace Kanboard\Plugin\Gumshoe\Test\Fakes {
    use Kanboard\Plugin\Vault\Secrets\SecretValue;
    use Kanboard\Plugin\Vault\Secrets\ServiceSecretException;

    final class FakeVaultSecrets
    {
        public array $reads = [];
        public ?\WeakReference $lastValue = null;
        public ?string $refusal = null;
        public bool $ready = true;

        public function __construct(private readonly \Closure $issueSecret)
        {
        }

        public function available(): bool
        {
            return $this->ready;
        }

        public function read(string $consumer, #[\SensitiveParameter] string $ref, ?string $jobRef = null): SecretValue
        {
            $this->reads[] = [$consumer, $ref, $jobRef];
            if ($this->refusal !== null) {
                throw new ServiceSecretException($this->refusal);
            }
            $secret = ($this->issueSecret)($ref);
            $this->lastValue = \WeakReference::create($secret);
            return $secret;
        }
    }
}
