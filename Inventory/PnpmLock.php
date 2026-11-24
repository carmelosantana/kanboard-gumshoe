<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use Generator;
use UnexpectedValueException;

final class PnpmLock
{
    public static function parse(string $contents, Limits $limits): ParseResult
    {
        $documents = Yaml::parseDocuments($contents);
        if ($documents instanceof ParseResult) {
            return $documents;
        }
        if ($documents === []) {
            return new ParseResult([], 'parse_error');
        }

        $majors = [];
        foreach ($documents as $document) {
            $version = $document['lockfileVersion'] ?? null;
            if (!is_string($version) && !is_int($version) && !is_float($version)) {
                return new ParseResult([], 'parse_error');
            }
            if (preg_match('/\A([69])(?:\.\d+)*\z/', (string) $version, $match) !== 1) {
                return new ParseResult([], 'unsupported');
            }
            $majors[] = (int) $match[1];
        }

        $deps = [];
        try {
            foreach ($documents as $index => $document) {
                foreach (self::rows($document, $majors[$index]) as $dependency) {
                    if (!$limits->allowsDependencies(count($deps) + 1)) {
                        return new ParseResult([], 'too_many');
                    }
                    $deps[] = $dependency;
                }
            }
        } catch (UnexpectedValueException) {
            return new ParseResult([], 'parse_error');
        }

        return new ParseResult($deps);
    }

    /** @return Generator<Dependency> */
    private static function rows(array $document, int $major): Generator
    {
        $packages = self::map($document, 'packages');
        $settings = self::map($document, 'settings');
        $defaultRegistry = self::usesDefaultRegistry($document) && self::usesDefaultRegistry($settings);
        $scopes = $major === 9 ? self::snapshotScopes($document) : [];

        $rows = [];
        foreach ($packages as $key => $package) {
            if (!is_string($key) || !is_array($package)) {
                throw new UnexpectedValueException();
            }

            $id = self::packageId($key, $major);
            $base = explode('(', $id, 2)[0];
            $separator = strpos($base, '@', 1);
            $name = substr($base, 0, $separator);
            $version = substr($base, $separator + 1);
            $resolution = self::map($package, 'resolution');
            $queryable = preg_match('/\A\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?\z/', $version) === 1;
            $public = $queryable && (array_key_exists('tarball', $resolution)
                ? self::isNpmRegistry($resolution['tarball'])
                : $defaultRegistry && !isset($resolution['type']));
            $scope = $major === 6 ? (($package['dev'] ?? false) === true ? 'dev' : 'prod') : ($scopes[$base] ?? 'prod');

            if (isset($rows[$base])) {
                $public = $public && $rows[$base]->registry_evidence === 'npmjs';
                $scope = $rows[$base]->scope === 'prod' ? 'prod' : $scope;
            }
            $rows[$base] = new Dependency(
                'npm',
                $name,
                $version,
                $scope,
                null,
                $queryable ? Dependency::QUERY_PACKAGE : Dependency::QUERY_NONE,
                $public ? 'npmjs' : null,
            );
        }

        yield from $rows;
    }

    private static function packageId(string $key, int $major): string
    {
        if ($major === 6) {
            $key = str_starts_with($key, '/') ? substr($key, 1) : $key;
        }

        $separator = $major === 6 ? '[@/]' : '@';
        if (preg_match('#\A((?:@[\w.~-]+/)?[\w.~-]+)'.$separator.'([^\s(][^\s]*)\z#D', $key, $identity) !== 1) {
            throw new UnexpectedValueException();
        }
        return $identity[1].'@'.$identity[2];
    }

    /** @return array<string, string> */
    private static function snapshotScopes(array $document): array
    {
        $snapshots = self::map($document, 'snapshots');
        $importers = self::map($document, 'importers');
        $scopes = [];
        $visited = [];
        // Walk production roots first so any production path wins over development.
        foreach (['prod' => ['dependencies', 'optionalDependencies'], 'dev' => ['devDependencies']] as $scope => $fields) {
            $pending = [];
            foreach ($importers as $importer) {
                if (!is_array($importer)) {
                    throw new UnexpectedValueException();
                }
                self::queueReferences($pending, $importer, $fields, $snapshots);
            }

            while (($id = array_pop($pending)) !== null) {
                if (isset($visited[$id])) {
                    continue;
                }
                $visited[$id] = true;
                $base = explode('(', $id, 2)[0];
                $scopes[$base] ??= $scope;
                self::queueReferences($pending, $snapshots[$id], ['dependencies', 'optionalDependencies'], $snapshots);
            }
        }
        return $scopes;
    }

    private static function queueReferences(array &$pending, array $node, array $fields, array $snapshots): void
    {
        foreach ($fields as $field) {
            foreach (self::map($node, $field) as $name => $entry) {
                $version = is_array($entry) ? ($entry['version'] ?? null) : $entry;
                if (!is_string($version) || !is_string($name)) {
                    throw new UnexpectedValueException();
                }
                $id = isset($snapshots[$version]) ? $version : $name.'@'.$version;
                if (array_key_exists($id, $snapshots)) {
                    if (!is_array($snapshots[$id])) {
                        throw new UnexpectedValueException();
                    }
                    $pending[] = $id;
                }
            }
        }
    }

    private static function map(array $document, string $key): array
    {
        if (!array_key_exists($key, $document)) {
            return [];
        }
        if (!is_array($document[$key]) || ($document[$key] !== [] && array_is_list($document[$key]))) {
            throw new UnexpectedValueException();
        }
        return $document[$key];
    }

    private static function usesDefaultRegistry(array $settings): bool
    {
        foreach ($settings as $key => $value) {
            if ($key === 'registry' && !self::isNpmRegistry($value)) {
                return false;
            }
            if ($key === 'registries' || (is_string($key) && str_ends_with($key, ':registry'))) {
                return false;
            }
        }
        return true;
    }

    private static function isNpmRegistry(mixed $url): bool
    {
        if (!is_string($url)) {
            return false;
        }
        $parts = parse_url($url);
        return in_array(strtolower($parts['scheme'] ?? ''), ['http', 'https'], true)
            && strtolower($parts['host'] ?? '') === 'registry.npmjs.org'
            && !isset($parts['user']);
    }
}
