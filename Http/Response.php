<?php

namespace Kanboard\Plugin\Gumshoe\Http;

final readonly class Response
{
    /** @var array<string, string> */
    public array $headers;

    public function __construct(
        public int $status,
        #[\SensitiveParameter] array $headers = [],
        #[\SensitiveParameter] public string $body = '',
        public ?int $retryAt = null,
    ) {
        $this->headers = array_change_key_case($headers, CASE_LOWER);
    }

    public function header(string $name): ?string
    {
        return $this->headers[strtolower($name)] ?? null;
    }
}
