<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use Generator;
use UnexpectedValueException;

final class NpmLock
{
    public static function parse(string $contents, Limits $limits): ParseResult
    {
        $lock = $limits->decodeJson($contents);
        if ($lock instanceof ParseResult) {
            return $lock;
        }

        $lockVersion = $lock['lockfileVersion'] ?? null;
        if (!is_int($lockVersion)) {
            return new ParseResult([], 'parse_error');
        }
        if (!in_array($lockVersion, [1, 2, 3], true)) {
            return new ParseResult([], 'unsupported');
        }

        $deps = [];
        try {
            $rows = $lockVersion === 1
                ? self::legacyRows($lock['dependencies'] ?? [Limits::JSON_OBJECT_MARKER => true])
                : self::packageRows($lock['packages'] ?? null);
            foreach ($rows as [$name, $package, $workspace]) {
                if (!$limits->allowsDependencies(count($deps) + 1)) {
                    return new ParseResult([], 'too_many');
                }
                $deps[] = self::dependency($name, $package, $workspace);
            }
        } catch (UnexpectedValueException) {
            return new ParseResult([], 'parse_error');
        }

        return new ParseResult($deps);
    }

    /** @return Generator<array{string, array, bool}> */
    private static function legacyRows(mixed $packages): Generator
    {
        if (!is_array($packages) || array_is_list($packages)) {
            throw new UnexpectedValueException();
        }

        foreach ($packages as $name => $package) {
            if ($name === Limits::JSON_OBJECT_MARKER) {
                continue;
            }
            if (!is_array($package) || array_is_list($package)) {
                throw new UnexpectedValueException();
            }
            yield [(string) $name, $package, false];

            if (array_key_exists('dependencies', $package)) {
                yield from self::legacyRows($package['dependencies']);
            }
        }
    }

    /** @return Generator<array{string, array, bool}> */
    private static function packageRows(mixed $packages): Generator
    {
        if (!is_array($packages) || array_is_list($packages)) {
            throw new UnexpectedValueException();
        }

        foreach ($packages as $path => $package) {
            if ($path === '' || $path === Limits::JSON_OBJECT_MARKER) {
                continue;
            }
            if (!is_array($package) || array_is_list($package)) {
                throw new UnexpectedValueException();
            }
            if (($package['link'] ?? false) === true) {
                continue;
            }

            $absolutePath = '/'.$path;
            $moduleOffset = strrpos($absolutePath, '/node_modules/');
            // Local members have their own entries. Their node_modules links were skipped above.
            $workspace = $moduleOffset === false;
            $name = $workspace ? basename((string) $path) : substr($absolutePath, $moduleOffset + strlen('/node_modules/'));
            yield [$name, $package, $workspace];
        }
    }

    private static function dependency(string $name, array $package, bool $workspace): Dependency
    {
        $name = $package['name'] ?? $name;
        $version = $package['version'] ?? null;
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
            ($package['dev'] ?? false) === true ? 'dev' : 'prod',
            $workspace ? 'workspace' : null,
            $version === null ? Dependency::QUERY_NONE : Dependency::QUERY_PACKAGE,
            !$workspace && self::isNpmRegistryTarball($package['resolved'] ?? null, $name, $version) ? 'npmjs' : null,
        );
    }

    private static function isNpmRegistryTarball(mixed $resolved, string $name, ?string $version): bool
    {
        if (!is_string($resolved) || $version === null || $version === ''
            || strpbrk($name, "?#\\") !== false || strpbrk($version, "/?#\\") !== false) {
            return false;
        }

        $registry = 'https://registry.npmjs.org/';
        $slash = strpos($name, '/');
        if ($slash !== false && (!str_starts_with($name, '@') || $slash !== strrpos($name, '/'))) {
            return false;
        }
        $basename = $slash === false ? $name : substr($name, $slash + 1);
        $tarball = "/-/{$basename}-{$version}.tgz";
        if ($resolved === $registry.$name.$tarball) {
            return true;
        }

        return $slash !== false
            && ($resolved === $registry.str_replace('/', '%2f', $name).$tarball
                || $resolved === $registry.str_replace('/', '%2F', $name).$tarball);
    }
}
