<?php

namespace Kanboard\Plugin\Gumshoe\Advisory;

final class VersionRange
{
    private const NPM_VERSION = '/\Av?(0|[1-9]\d*)(?:\.(0|[1-9]\d*)(?:\.(0|[1-9]\d*))?)?(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?\z/';
    private const COMPOSER_VERSION = '/\Av?(\d+(?:\.\d+){0,3})(?:[-.]?(dev|alpha|a|beta|b|rc|stable|patch|pl|p)(?:[.-]?(\d+))?)?\z/i';

    public static function matches(string $ecosystem, string $version, string $range): bool
    {
        $actual = self::parse($ecosystem, $version, false);
        if ($actual === null) {
            return false;
        }
        foreach (explode(',', $range) as $constraint) {
            if (preg_match('/\A\s*(<=|>=|=|<|>)?\s*([^\s]+)\s*\z/', $constraint, $parts) !== 1) {
                return false;
            }
            [, $operator, $target] = $parts;
            $bound = self::parse($ecosystem, $target, true);
            if ($bound === null) {
                return false;
            }
            $cmp = $ecosystem === 'composer'
                ? version_compare($actual, $bound)
                : self::compareNpm($actual, $bound, $operator);
            if (!match ($operator) {
                '<' => $cmp < 0,
                '<=' => $cmp <= 0,
                '>' => $cmp > 0,
                '>=' => $cmp >= 0,
                default => $cmp === 0,
            }) {
                return false;
            }
        }
        return true;
    }

    private static function parse(string $ecosystem, string $version, bool $bound): array|string|null
    {
        if ($ecosystem === 'composer' && preg_match(self::COMPOSER_VERSION, $version, $matches) === 1) {
            $numeric = implode('.', array_pad(explode('.', $matches[1]), 4, '0'));
            $suffix = strtolower($matches[2] ?? '');
            $suffix = match ($suffix) {
                'stable' => '',
                'patch' => 'pl',
                default => $suffix,
            };
            return $numeric.($suffix === '' ? '' : '-'.$suffix.($matches[3] ?? ''));
        }
        if ($ecosystem !== 'npm' || preg_match(self::NPM_VERSION, $version, $matches, PREG_UNMATCHED_AS_NULL) !== 1) {
            return null;
        }
        $core = array_values(array_filter(array_slice($matches, 1, 3), static fn (?string $part): bool => $part !== null));
        $pre = $matches[4] === null ? [] : explode('.', $matches[4]);
        if (count($core) < 3 && (!$bound || $pre !== [])) {
            return null;
        }
        foreach ($pre as $identifier) {
            if (ctype_digit($identifier) && strlen($identifier) > 1 && $identifier[0] === '0') {
                return null;
            }
        }
        return [$core, $pre];
    }

    private static function compareNpm(array $actual, array $bound, string $operator): int
    {
        [$actualCore, $actualPre] = $actual;
        [$boundCore, $boundPre] = $bound;
        // Partial npm boundaries compare against either the entire prefix or its first release.
        if (in_array($operator, ['', '=', '<=', '>'], true)) {
            $actualCore = array_slice($actualCore, 0, count($boundCore));
        } else {
            $boundCore = array_pad($boundCore, 3, '0');
        }
        foreach ($actualCore as $index => $number) {
            $cmp = self::compareNumber($number, $boundCore[$index]);
            if ($cmp !== 0) {
                return $cmp;
            }
        }
        if (count($boundCore) < 3 || $actualPre === [] || $boundPre === []) {
            return count($boundCore) < 3 ? 0 : ($boundPre !== []) <=> ($actualPre !== []);
        }
        foreach ($actualPre as $index => $part) {
            if (!isset($boundPre[$index])) {
                return 1;
            }
            $other = $boundPre[$index];
            $numeric = ctype_digit($part);
            $otherNumeric = ctype_digit($other);
            $cmp = match (true) {
                $numeric && $otherNumeric => self::compareNumber($part, $other),
                $numeric !== $otherNumeric => $otherNumeric <=> $numeric,
                default => strcmp($part, $other),
            };
            if ($cmp !== 0) {
                return $cmp;
            }
        }
        return count($actualPre) <=> count($boundPre);
    }

    private static function compareNumber(string $left, string $right): int
    {
        return (strlen($left) <=> strlen($right)) ?: strcmp($left, $right);
    }
}
