<?php

namespace Kanboard\Plugin\Gumshoe\Egress;

use Kanboard\Plugin\Gumshoe\Inventory\Dependency;

final readonly class Policy
{
    private const NPM_REGISTRY = 'registry.npmjs.org';
    private const CREDENTIAL = '/(?:gh[pours]_|github_pat_|glpat-|xox[abp]-|AKIA[0-9A-Z]{16})/';

    /** @var list<string> */
    private array $denyPrefixes;

    /**
     * @param list<string> $denyPrefixes
     * @param array<string, bool|null> $githubVisibility Current-run GitHub observations keyed by lowercase owner/repo.
     *                                                  True means GitHub explicitly reported the repo public.
     */
    public function __construct(
        array $denyPrefixes = [],
        private array $githubVisibility = [],
    ) {
        $prefixes = [];
        foreach ($denyPrefixes as $prefix) {
            $prefix = strtolower(trim($prefix));
            if ($prefix !== '') {
                $prefixes[] = $prefix;
            }
        }
        $this->denyPrefixes = $prefixes;
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
        if (!self::isQueryable($dep->ecosystem, $dep->name, $dep->version ?? '', $dep->query_type)) {
            return 'unqueryable';
        }

        foreach ($this->denyPrefixes as $prefix) {
            if (str_starts_with($name, $prefix)) {
                return 'denied';
            }
        }

        $public = match ($dep->ecosystem) {
            'composer' => $dep->registry_evidence === 'packagist',
            'npm' => $dep->registry_evidence === 'npmjs'
                && in_array($lockfileKind, ['npm', 'pnpm'], true)
                && (!$dep->evidence_inferred || ($lockfileKind === 'pnpm' && self::usesNpmDefault($name, $registryConfig))),
            'actions' => ($this->githubVisibility[$name] ?? null) === true,
        };

        return $public ? 'public' : 'private';
    }

    public function isCoverageGap(Dependency $dep, string $verdict): bool
    {
        return $dep->source !== 'workspace' && $verdict !== 'public';
    }

    /** Pending rows carry the verdict from inventory, which has the registry and visibility evidence. */
    public static function allowsPendingQuery(array $row): bool
    {
        return $row['egress'] === 'public'
            && self::isQueryable($row['ecosystem'], $row['name'], $row['version'], $row['query_type']);
    }

    private static function isQueryable(string $ecosystem, string $name, string $version, string $queryType): bool
    {
        if (strlen($version) > 64 || preg_match(self::CREDENTIAL, $name) || preg_match(self::CREDENTIAL, $version)) {
            return false;
        }
        // Commit queries carry a fixed-format hash, which also matches the opaque package-version filter.
        if ($ecosystem !== 'actions' && preg_match('/[0-9A-Za-z_-]{32}/', $version)) {
            return false;
        }

        return match ($ecosystem) {
            'npm' => $queryType === Dependency::QUERY_PACKAGE
                && strlen($name) <= 214
                && preg_match('~\A(@[a-z0-9][a-z0-9._-]*/)?[a-z0-9][a-z0-9._-]*\z~', $name) === 1
                && preg_match('/\A\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?\z/', $version) === 1,
            'composer' => $queryType === Dependency::QUERY_PACKAGE
                && preg_match('~\A[a-z0-9]([_.-]?[a-z0-9]+)*/[a-z0-9](([_.]|-{1,2})?[a-z0-9]+)*\z~', $name) === 1
                && preg_match('/\Av?\d+(\.\d+){0,3}(-?(alpha|beta|RC|patch|p|pl|dev)\.?\d*)?\z/i', $version) === 1,
            'actions' => $queryType === Dependency::QUERY_COMMIT
                && preg_match('~\A[a-z0-9][a-z0-9-]{0,38}/(?!\.{1,2}\z)[a-z0-9_.-]{1,100}\z~i', $name) === 1
                && preg_match('/\A[0-9a-f]{40}\z/', $version) === 1,
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
