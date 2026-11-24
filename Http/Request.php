<?php

namespace Kanboard\Plugin\Gumshoe\Http;

final readonly class Request
{
    public function __construct(
        public string $operation,
        #[\SensitiveParameter] public string $url,
        public ?string $owner = null,
        public string $method = 'GET',
        #[\SensitiveParameter] public ?string $body = null,
        #[\SensitiveParameter] public array $headers = [],
    ) {
    }

    public function withUrl(#[\SensitiveParameter] string $url): self
    {
        return new self($this->operation, $url, $this->owner, $this->method, $this->body, $this->headers);
    }
}
