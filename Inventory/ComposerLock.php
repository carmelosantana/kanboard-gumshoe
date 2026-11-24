<?php

namespace Kanboard\Plugin\Gumshoe\Inventory;

use stdClass;

final class ComposerLock
{
    public static function parse(string $contents, Limits $limits): ParseResult
    {
        $lock = $limits->decodeJson($contents);
        if ($lock instanceof ParseResult) {
            return $lock;
        }

        $groups = [
            'prod' => $lock->packages ?? null,
            'dev' => $lock->{'packages-dev'} ?? [],
        ];
        $deps = [];
        foreach ($groups as $scope => $packages) {
            if (!is_array($packages)) {
                return new ParseResult([], 'parse_error');
            }
            if (!$limits->allowsDependencies(count($deps) + count($packages))) {
                return new ParseResult([], 'too_many');
            }

            foreach ($packages as $package) {
                if (!$package instanceof stdClass || !is_string($package->name ?? null)
                    || !is_string($package->version ?? null)) {
                    return new ParseResult([], 'parse_error');
                }

                $version = $package->version;
                if (str_starts_with($version, 'v')) {
                    $version = substr($version, 1);
                }

                $reference = $package->source->reference ?? null;
                $deps[] = new Dependency(
                    'composer',
                    $package->name,
                    $version,
                    $scope,
                    ($package->source->type ?? null) === 'git' && is_string($reference) ? $reference : null,
                    Dependency::QUERY_PACKAGE,
                    ($package->{'notification-url'} ?? null) === 'https://packagist.org/downloads/' ? 'packagist' : null,
                );
            }
        }

        return new ParseResult($deps);
    }
}
