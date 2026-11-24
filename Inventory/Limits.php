<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use JsonException;
use stdClass;

final readonly class Limits
{
    public const MAX_FILE_BYTES = 10 * 1024 * 1024;
    public const MAX_REPO_LOCKFILES = 50;
    public const MAX_REPO_DEPS = 200_000;
    public const JSON_DEPTH = 64;

    public function __construct(public int $repoRows = 0)
    {
    }

    public function allowsDependencies(int $fileRows): bool
    {
        return $fileRows <= self::MAX_REPO_DEPS - $this->repoRows;
    }

    public function decodeJson(string $contents): stdClass|ParseResult
    {
        if (strlen($contents) > self::MAX_FILE_BYTES) {
            return new ParseResult([], 'too_large');
        }

        try {
            $data = json_decode($contents, false, self::JSON_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return new ParseResult([], 'parse_error');
        }

        return $data instanceof stdClass ? $data : new ParseResult([], 'parse_error');
    }
}
