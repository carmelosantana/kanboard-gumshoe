<?php

namespace Kanboard\Plugin\Gumshoe\Egress;

use Kanboard\Plugin\Gumshoe\Inventory\Dependency;

final readonly class Policy
{
    private const NPM_REGISTRY = 'registry.npmjs.org';

    /**
     * @param list<string> $denyPrefixes
     * @param array<string, bool|null> $githubVisibility Current-run GitHub observations keyed by lowercase owner/repo.
     *                                                  True means GitHub explicitly reported the repo public.
     */
    public function __construct(
        private array $denyPrefixes = [],
        private array $githubVisibility = [],
    ) {
    }

    /**
     * Inferred pnpm evidence requires the recorded registry configuration.
     *
     * @param array<string, string>|string $registryConfig TreeReader's registry host map or 'unknown'.
     */
    public function verdict(
        Dependency $dep,
        ?string $lockfileKind = null,
        array|string $registryConfig = 'unknown',
    ): string {
        if ($dep->source === 'workspace') {
            return 'private';
        }

        $name = $dep->ecosystem === 'actions' ? strtolower($dep->name) : $dep->name;
        if (preg_match('/\A[\x21-\x7e]{1,128}\z/', $dep->version ?? '') !== 1 || !self::isQueryable($dep, $name)) {
            return 'unqueryable';
        }

        foreach ($this->denyPrefixes as $prefix) {
            if ($prefix !== '' && str_starts_with($name, $prefix)) {
                return 'denied';
            }
        }

        $public = match ($dep->ecosystem) {
            'composer' => $dep->registry_evidence === 'packagist',
            'npm' => $dep->registry_evidence === 'npmjs'
                && (!$dep->evidence_inferred || ($lockfileKind === 'pnpm' && self::usesNpmDefault($name, $registryConfig))),
            'actions' => ($this->githubVisibility[$name] ?? null) === true,
        };

        return $public ? 'public' : 'private';
    }

    public function isCoverageGap(Dependency $dep, string $verdict): bool
    {
        return $dep->source !== 'workspace' && $verdict !== 'public';
    }

    private static function isQueryable(Dependency $dep, string $name): bool
    {
        return match ($dep->ecosystem) {
            'npm' => $dep->query_type === Dependency::QUERY_PACKAGE
                && strlen($name) <= 214
                && preg_match('~\A(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\z~', $name) === 1,
            'composer' => $dep->query_type === Dependency::QUERY_PACKAGE
                && preg_match('~\A[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*\z~', $name) === 1,
            'actions' => $dep->query_type === Dependency::QUERY_COMMIT
                && preg_match('~\A[a-z0-9][a-z0-9-]{0,38}/(?!\.{1,2}\z)[a-z0-9_.-]{1,100}\z~', $name) === 1
                && preg_match('/\A[0-9a-f]{40}\z/i', $dep->version ?? '') === 1,
            default => false,
        };
    }

    private static function usesNpmDefault(string $name, array|string $config): bool
    {
        if (!is_array($config) || (array_key_exists('registry', $config) && $config['registry'] !== self::NPM_REGISTRY)) {
            return false;
        }

        return $name[0] !== '@' || !array_key_exists(explode('/', $name, 2)[0], $config);
    }
}
