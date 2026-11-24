<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use UnexpectedValueException;

final class PnpmLock
{
    private const REGISTRY_VERSION = '\d+\.\d+\.\d+(?:-[\w.-]+)?(?:\+[\w.-]+)?';

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
                $remaining = Limits::MAX_REPO_DEPS - $limits->repoRows - count($deps);
                $rows = self::rows($document, $majors[$index], $remaining);
                if ($rows === null) {
                    return new ParseResult([], 'too_many');
                }
                foreach ($rows as $dependency) {
                    $deps[] = $dependency;
                }
                unset($rows);
            }
        } catch (UnexpectedValueException) {
            return new ParseResult([], 'parse_error');
        }

        return new ParseResult($deps);
    }

    /** @return array<string, Dependency>|null Null if the unique rows exceed the budget. */
    private static function rows(array $document, int $major, int $remaining): ?array
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
            if ($id === null && $major !== 6) {
                throw new UnexpectedValueException();
            }
            $base = $id === null ? 'opaque:'.$key : explode('(', $id, 2)[0];
            if (!isset($rows[$base]) && count($rows) >= $remaining) {
                return null;
            }

            $resolution = self::map($package, 'resolution');
            $scope = $major === 6 && ($package['dev'] ?? false) === true ? 'dev' : 'prod';
            if ($id === null) {
                $rows[$base] = new Dependency(
                    'npm',
                    is_string($package['name'] ?? null) ? $package['name'] : $key,
                    is_string($package['version'] ?? null) ? $package['version'] : null,
                    $scope,
                    null,
                    Dependency::QUERY_NONE,
                    null,
                );
                continue;
            }
            $separator = strpos($base, '@', 1);
            $name = substr($base, 0, $separator);
            $version = substr($base, $separator + 1);
            $queryable = preg_match('/\A'.self::REGISTRY_VERSION.'\z/', $version) === 1;
            $hasTarball = array_key_exists('tarball', $resolution);
            $public = $queryable && ($hasTarball
                ? $resolution['tarball'] === 'https://registry.npmjs.org/'.$name.'/-/'.basename($name).'-'.$version.'.tgz'
                : $defaultRegistry && !isset($resolution['type']));
            $inferred = !$hasTarball;
            $scope = $scopes[$base] ?? $scope;

            if (isset($rows[$base])) {
                $public = $public && $rows[$base]->registry_evidence === 'npmjs';
                $inferred = $inferred || $rows[$base]->evidence_inferred;
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
                $public && $inferred,
            );
        }

        return $rows;
    }

    private static function packageId(string $key, int $major): ?string
    {
        if ($major === 6) {
            $key = str_starts_with($key, '/') ? substr($key, 1) : $key;
        }

        $version = $major === 6 ? '[@/]('.self::REGISTRY_VERSION.'(?:\([^\s]*\))?)' : '@([^\s(][^\s]*)';
        if (preg_match('#\A((?:@[\w.~-]+/)?[\w.~-]+)'.$version.'\z#D', $key, $identity) !== 1) {
            return null;
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
