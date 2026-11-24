<?php

namespace Kanboard\Plugin\Gumshoe\Http;

interface Transport
{
    /** Send one validated hop. The headers may include a credential and must not be retained. */
    public function send(#[\SensitiveParameter] Request $request, #[\SensitiveParameter] array $headers): Response;
}
