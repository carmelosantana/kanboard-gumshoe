<?php

namespace Kanboard\Plugin\Gumshoe\Test\Fakes;

use Kanboard\Plugin\Gumshoe\Http\Request;
use Kanboard\Plugin\Gumshoe\Http\Response;
use Kanboard\Plugin\Gumshoe\Http\Transport;

final class FakeTransport implements Transport
{
    public array $requests = [];
    public array $authenticated = [];

    public function __construct(private array $responses = [])
    {
    }

    public function send(#[\SensitiveParameter] Request $request, #[\SensitiveParameter] array $headers): Response
    {
        $this->requests[] = $request;
        $this->authenticated[] = isset($headers['Authorization']);
        $result = array_shift($this->responses) ?? new Response(200);
        return is_callable($result) ? $result($headers) : $result;
    }
}
