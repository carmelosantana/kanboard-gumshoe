<?php

namespace Kanboard\Plugin\Gumshoe\Secrets;

use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Vault\Secrets\SecretValue;

interface TokenSource
{
    public function available(): bool;

    public function forOwner(string $owner, ?string $jobRef = null): ?SecretValue;

    /** @return array{status: string, expiresAt: ?int, retryAt: ?int} */
    public function status(string $owner): array;

    public function observeGithub(string $owner, #[\SensitiveParameter] Response $response, int $now): void;

    public function endSlice(): void;
}
