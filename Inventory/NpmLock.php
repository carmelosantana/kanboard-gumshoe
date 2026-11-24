<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use Generator;
use stdClass;
use UnexpectedValueException;

final class NpmLock
{
    public static function parse(string $contents, Limits $limits): ParseResult
    {
        $lock = $limits->decodeJson($contents);
        if ($lock instanceof ParseResult) {
            return $lock;
        }

        $lockVersion = $lock->lockfileVersion ?? null;
        if (!is_int($lockVersion)) {
            return new ParseResult([], 'parse_error');
        }
        if (!in_array($lockVersion, [1, 2, 3], true)) {
            return new ParseResult([], 'unsupported');
        }

        $deps = [];
        try {
            $rows = $lockVersion === 1
                ? self::legacyRows($lock->dependencies ?? new stdClass())
                : self::packageRows($lock->packages ?? null);
            foreach ($rows as $dependency) {
                if (!$limits->allowsDependencies(count($deps) + 1)) {
                    return new ParseResult([], 'too_many');
                }
                $deps[] = $dependency;
            }
        } catch (UnexpectedValueException) {
            return new ParseResult([], 'parse_error');
        }

        return new ParseResult($deps);
    }

    /** @return Generator<Dependency> */
    private static function legacyRows(mixed $packages): Generator
    {
        if (!$packages instanceof stdClass) {
            throw new UnexpectedValueException();
        }

        foreach ($packages as $name => $package) {
            if (!$package instanceof stdClass) {
                throw new UnexpectedValueException();
            }
            yield self::dependency($name, $package);

            if (property_exists($package, 'dependencies')) {
                yield from self::legacyRows($package->dependencies);
            }
        }
    }

    /** @return Generator<Dependency> */
    private static function packageRows(mixed $packages): Generator
    {
        if (!$packages instanceof stdClass) {
            throw new UnexpectedValueException();
        }

        foreach ($packages as $path => $package) {
            if ($path === '') {
                continue;
            }
            if (!$package instanceof stdClass) {
                throw new UnexpectedValueException();
            }
            if (($package->link ?? false) === true) {
                continue;
            }

            $absolutePath = '/'.$path;
            $moduleOffset = strrpos($absolutePath, '/node_modules/');
            // Local members have their own entries. Their node_modules links were skipped above.
            $workspace = $moduleOffset === false;
            $name = $workspace ? basename($path) : substr($absolutePath, $moduleOffset + strlen('/node_modules/'));
            yield self::dependency($name, $package, $workspace);
        }
    }

    private static function dependency(string $name, stdClass $package, bool $workspace = false): Dependency
    {
        $name = $package->name ?? $name;
        $version = $package->version ?? null;
        if (!is_string($name) || ($version !== null && !is_string($version))) {
            throw new UnexpectedValueException();
        }

        if ($version !== null && str_starts_with($version, 'npm:')) {
            if (preg_match('~^npm:((?:@[^/@]+/)?[^/@]+)@(.+)$~D', $version, $alias) !== 1) {
                throw new UnexpectedValueException();
            }
            [, $name, $version] = $alias;
        }

        return new Dependency(
            'npm',
            $name,
            $version,
            ($package->dev ?? false) === true ? 'dev' : 'prod',
            $workspace ? 'workspace' : null,
            $version === null ? Dependency::QUERY_NONE : Dependency::QUERY_PACKAGE,
            !$workspace && self::isNpmRegistry($package->resolved ?? null) ? 'npmjs' : null,
        );
    }

    private static function isNpmRegistry(mixed $resolved): bool
    {
        if (!is_string($resolved)) {
            return false;
        }

        $url = parse_url($resolved);
        return in_array(strtolower($url['scheme'] ?? ''), ['http', 'https'], true)
            && strtolower($url['host'] ?? '') === 'registry.npmjs.org'
            && !isset($url['user']);
    }
}
