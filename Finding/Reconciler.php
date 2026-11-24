<?php

namespace Kanboard\Plugin\Gumshoe\Finding;

use InvalidArgumentException;
use Kanboard\Plugin\Gumshoe\Model\FindingModel;

final readonly class Reconciler
{
    public function __construct(private FindingModel $findings)
    {
    }

    /**
     * Apply one repo's Matcher exposures. Supply an outcome only from this run's
     * inventory, and assert advisory completeness only when the source results
     * supplied to Matcher are complete. The hourly job uses positive matches only.
     *
     * @param list<array{group_id: int, ecosystem: string, package: string, repo_id: int, lockfile_id: int, version: string}> $matches
     * @return array<int, array{from: ?string, to: string, ever_affected: bool, comment: ?string}>
     *     Transitions keyed by finding ID for the board sync. The comment is text for a new unknown transition.
     */
    public function apply(
        int $runId,
        int $repoId,
        ?string $outcome,
        array $matches,
        bool $advisorySourcesComplete,
        int $now,
    ): array {
        return $this->findings->transaction(function () use ($runId, $repoId, $outcome, $matches, $advisorySourcesComplete, $now): array {
            $context = $this->findings->context($runId, $repoId);
            if (!(int) $context['enabled']) {
                return [];
            }

            $inventory = $context['job'] === 'gumshoe.inventory';
            $previous = $this->findings->forRepo($repoId);
            if (in_array($inventory ? $outcome : $context['outcome'], ['inaccessible', 'out_of_watch'], true)) {
                if (!$inventory) {
                    return [];
                }
                $comment = $context['owner'].'/'.$context['repo']." is no longer scanned ($outcome); its status is unknown.";
                $states = array_fill_keys(array_keys($previous), 'unknown');
                foreach ($previous as $findingId => $row) {
                    if ($row['state'] !== 'affected') {
                        unset($states[$findingId]);
                    }
                }

                return $this->applyStates($repoId, $previous, $states, $comment);
            }

            $seen = [];
            $states = [];
            foreach ($matches as $match) {
                if ($match['repo_id'] !== $repoId) {
                    throw new InvalidArgumentException('Match belongs to a different repository.');
                }
                $findingId = $this->findings->recordExposure($match, $now);
                $seen[$findingId][$match['lockfile_id']][$match['version']] = true;
                $states[$findingId] = 'affected';
            }

            if ($inventory && $outcome === 'complete' && $advisorySourcesComplete && !$this->findings->hasIncompleteLockfiles($repoId)) {
                foreach ($this->resolvedFindings($runId, $repoId, $seen) as $findingId) {
                    $states[$findingId] = 'fixed';
                }
            }

            return $this->applyStates($repoId, $previous, $states);
        });
    }

    /** Retire only unmatched exposures with complete answers, then aggregate by repo. */
    private function resolvedFindings(int $runId, int $repoId, array $seen): array
    {
        $stillActive = [];
        $retired = [];
        foreach ($this->findings->activeExposures($repoId) as $exposure) {
            $findingId = $exposure['finding_id'];
            if (isset($seen[$findingId][$exposure['lockfile_id']][$exposure['version']])
                || !$this->findings->hasCompleteAnswers($runId, $repoId, $exposure)) {
                $stillActive[$findingId] = true;
                continue;
            }

            $this->findings->retireExposure($repoId, $exposure);
            $retired[$findingId] = true;
        }

        return array_keys(array_diff_key($retired, $stillActive));
    }

    private function applyStates(int $repoId, array $previous, array $states, ?string $comment = null): array
    {
        $transitions = [];
        foreach ($states as $findingId => $state) {
            $row = $previous[$findingId] ?? null;
            $from = $row['state'] ?? null;
            if ($from === $state) {
                continue;
            }

            $this->findings->setRepoState($findingId, $repoId, $state, $row);
            $transitions[$findingId] = [
                'from' => $from,
                'to' => $state,
                'ever_affected' => !empty($row['ever_affected']),
                'comment' => $comment,
            ];
        }

        return $transitions;
    }
}
