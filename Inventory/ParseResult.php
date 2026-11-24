<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

final readonly class ParseResult
{
    /** @param list<Dependency> $deps */
    public function __construct(public array $deps, public string $status = 'ok')
    {
    }
}
