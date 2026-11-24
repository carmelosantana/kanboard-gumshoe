<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

final class Workflows
{
    public static function parse(string $contents, Limits $limits): ParseResult
    {
        $documents = Yaml::parseDocuments($contents);
        if ($documents instanceof ParseResult) {
            return $documents;
        }
        if (count($documents) !== 1 || !is_array($documents[0]['jobs'] ?? null)) {
            return new ParseResult([], 'parse_error');
        }

        $deps = [];
        foreach ($documents[0]['jobs'] as $job) {
            if (!is_array($job) || !is_array($job['steps'] ?? [])) {
                return new ParseResult([], 'parse_error');
            }

            $locations = [$job];
            foreach ($job['steps'] ?? [] as $step) {
                $locations[] = $step;
            }

            foreach ($locations as $location) {
                if (!is_array($location)) {
                    return new ParseResult([], 'parse_error');
                }
                if (!array_key_exists('uses', $location)) {
                    continue;
                }

                $reference = $location['uses'];
                if (!is_string($reference)) {
                    return new ParseResult([], 'parse_error');
                }
                if (str_starts_with($reference, './')) {
                    continue;
                }
                $dependency = self::dependency($reference);
                if ($dependency === null) {
                    return new ParseResult([], 'parse_error');
                }
                if (!$limits->allowsDependencies(count($deps) + 1)) {
                    return new ParseResult([], 'too_many');
                }
                $deps[] = $dependency;
            }
        }

        return new ParseResult($deps);
    }

    private static function dependency(string $reference): ?Dependency
    {
        if (str_starts_with($reference, 'docker://') && strlen($reference) > 9) {
            return new Dependency('docker', substr($reference, 9), null, 'action', null, Dependency::QUERY_NONE, null);
        }
        if (preg_match('~\A([a-z\d-]+/[a-z\d_.-]+)(?:/[^@\s]+)?@([^@\s]+)\z~i', $reference, $match) !== 1) {
            return null;
        }

        [, $repo, $ref] = $match;
        $pinned = preg_match('/\A[\da-f]{40}\z/i', $ref) === 1;
        return new Dependency(
            'actions',
            strtolower($repo),
            $pinned ? strtolower($ref) : $ref,
            'action',
            $pinned ? null : 'mutable',
            $pinned ? Dependency::QUERY_COMMIT : Dependency::QUERY_NONE,
            null,
        );
    }
}
