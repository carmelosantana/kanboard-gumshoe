<?php

namespace Kanboard\Plugin\Gumshoe\Finding;

use Kanboard\Plugin\Gumshoe\Advisory\GroupStore;
use Kanboard\Plugin\Gumshoe\Inventory\Dependency;

final readonly class Matcher
{
    public function __construct(private GroupStore $groups)
    {
    }

    /**
     * Return positive matches only. The caller determines completeness separately.
     *
     * @param iterable<array> $dependencies Inventory rows joined with repo_id from their lockfile.
     * @param iterable<array> $pending Pending-query rows from this run.
     * @param array<int, list<array>> $osvResults Completed OSV results keyed by pending row ID.
     * @param array<int, list<array>> $githubMatches Local GitHub malware matches keyed by dependency row ID.
     * @return array{
     *     exposures: list<array{group_id: int, ecosystem: string, package: string, repo_id: int, lockfile_id: int, version: string}>,
     *     coverage_gaps: array<int, int>,
     *     merged: array<int, int>
     * } Merges reported here map absorbed IDs to their surviving group for this call.
     */
    public function exposures(
        iterable $dependencies,
        iterable $pending,
        array $osvResults,
        array $githubMatches,
    ): array {
        $queryIds = [];
        foreach ($pending as $row) {
            if ($row['egress'] === 'public') {
                $queryIds[self::queryKey($row)] = (int) $row['id'];
            }
        }

        $coverageGaps = [];
        $candidates = [];
        $resolved = [];
        $merged = [];
        foreach ($dependencies as $dep) {
            $repo = (int) $dep['repo_id'];
            if ($dep['egress'] !== 'public') {
                if (($dep['source'] ?? null) !== 'workspace') {
                    $coverageGaps[$repo] = ($coverageGaps[$repo] ?? 0) + 1;
                }
                continue;
            }

            $queryId = $queryIds[self::queryKey($dep)] ?? null;
            $osv = $osvResults[$queryId] ?? [];
            $github = $dep['query_type'] === Dependency::QUERY_PACKAGE ? ($githubMatches[$dep['id']] ?? []) : [];
            foreach (self::aliasSets($osv, $github) as $aliases) {
                $aliasKey = serialize($aliases);
                if (!isset($resolved[$aliasKey])) {
                    $result = $this->groups->resolve($aliases);
                    $resolved[$aliasKey] = $result['group']['id'];
                    foreach ($result['merged'] as $absorbed) {
                        $merged[$absorbed] = $resolved[$aliasKey];
                    }
                }

                $candidates[] = [
                    'group_id' => $resolved[$aliasKey],
                    'ecosystem' => $dep['ecosystem'],
                    'package' => $dep['name'],
                    'repo_id' => $repo,
                    'lockfile_id' => (int) $dep['lockfile_id'],
                    'version' => $dep['version'],
                ];
            }
        }

        // Later matches can connect groups already seen in this pass.
        $exposures = [];
        foreach ($candidates as $exposure) {
            $exposure['group_id'] = self::survivor($exposure['group_id'], $merged);
            $exposures[serialize($exposure)] = $exposure;
        }

        return [
            'exposures' => array_values($exposures),
            'coverage_gaps' => $coverageGaps,
            'merged' => array_map(static fn (int $id): int => self::survivor($id, $merged), $merged),
        ];
    }

    private static function queryKey(array $row): string
    {
        return serialize([$row['query_type'], $row['ecosystem'], $row['name'], $row['version']]);
    }

    /** @return iterable<list<string>> */
    private static function aliasSets(array $osv, array $github): iterable
    {
        foreach ($osv as $advisory) {
            yield [$advisory['id'], ...($advisory['aliases'] ?? [])];
        }
        foreach ($github as $advisory) {
            $aliases = [$advisory['ghsa_id']];
            if (!empty($advisory['cve_id'])) {
                $aliases[] = $advisory['cve_id'];
            }
            yield $aliases;
        }
    }

    private static function survivor(int $id, array $merged): int
    {
        while (isset($merged[$id])) {
            $id = $merged[$id];
        }
        return $id;
    }
}
