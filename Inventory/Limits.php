<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use Generator;
use JsonException;

final readonly class Limits
{
    public const MAX_FILE_BYTES = 10 * 1024 * 1024;
    public const MAX_REPO_LOCKFILES = 50;
    public const MAX_REPO_DEPS = 200_000;
    public const JSON_DEPTH = 64;
    public const MAX_JSON_CONTAINERS = 60_000;
    public const JSON_OBJECT_MARKER = "\0";
    public const MAX_YAML_REFERENCES = 1_000;
    public const MAX_YAML_NODES = 500_000;

    public function __construct(public int $repoRows = 0)
    {
    }

    public function allowsDependencies(int $fileRows): bool
    {
        return $fileRows <= self::MAX_REPO_DEPS - $this->repoRows;
    }

    public function decodeJson(string $contents): array|ParseResult
    {
        if (strlen($contents) > self::MAX_FILE_BYTES) {
            return new ParseResult([], 'too_large');
        }
        $containers = 0;
        foreach (self::jsonStructure($contents) as $offset) {
            if ($contents[$offset] === '"') {
                return new ParseResult([], 'parse_error');
            }
            if (++$containers > self::MAX_JSON_CONTAINERS) {
                return new ParseResult([], 'too_many');
            }
        }

        $first = strspn($contents, " \t\r\n");
        if (($contents[$first] ?? null) !== '{') {
            return new ParseResult([], 'parse_error');
        }

        try {
            return json_decode(self::markJsonObjects($contents), true, self::JSON_DEPTH, JSON_THROW_ON_ERROR);
        } catch (JsonException) {
            return new ParseResult([], 'parse_error');
        }
    }

    // Yield structural openers and closing quotes of invalid NUL-prefixed property names.
    private static function jsonStructure(string $contents): Generator
    {
        $length = strlen($contents);
        $inString = false;
        $nulPrefix = false;
        for ($offset = 0; $offset < $length; ++$offset) {
            $offset += strcspn($contents, $inString ? '"\\' : '"{[', $offset);
            $byte = $contents[$offset] ?? null;
            if ($byte === '"') {
                if (!$inString) {
                    $nulPrefix = substr_compare($contents, '\\u0000', $offset + 1, 6) === 0;
                } elseif ($nulPrefix) {
                    $next = $offset + 1 + strspn($contents, " \t\r\n", $offset + 1);
                    if (($contents[$next] ?? null) === ':') {
                        yield $offset;
                    }
                }
                $inString = !$inString;
            } elseif ($inString && $byte === '\\') {
                ++$offset; // The next byte is escaped.
            } elseif ($byte !== null) {
                yield $offset;
            }
        }
    }

    private static function markJsonObjects(string $contents): string
    {
        // Associative decoding maps both {} and [] to []. Keep their shape, including
        // objects with numeric keys. The marker key is forbidden in the original JSON.
        $marked = '';
        $start = 0;
        foreach (self::jsonStructure($contents) as $offset) {
            if ($contents[$offset] !== '{') {
                continue;
            }
            $next = $offset + 1;
            $key = $next + strspn($contents, " \t\r\n", $next);
            $marked .= substr($contents, $start, $next - $start).'"\\u0000":true';
            if (($contents[$key] ?? null) !== '}') {
                $marked .= ',';
            }
            $start = $next;
        }

        return $marked.substr($contents, $start);
    }
}
