<?php

namespace Kanboard\Plugin\Gumshoe\Http;

final class HttpFailure extends \RuntimeException
{
    public function __construct(
        public readonly string $operation,
        public readonly ?string $host,
        public readonly ?int $status,
        public readonly string $reason,
    ) {
        parent::__construct($reason);
    }
}
