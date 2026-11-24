<?php

namespace Kanboard\Plugin\Gumshoe\Run;

use Closure;
use Kanboard\Plugin\Gumshoe\Advisory\AdvisoryCache;
use Kanboard\Plugin\Gumshoe\Advisory\GithubMalware;
use Kanboard\Plugin\Gumshoe\Advisory\GroupStore;
use Kanboard\Plugin\Gumshoe\Advisory\Kev;
use Kanboard\Plugin\Gumshoe\Advisory\Osv;
use Kanboard\Plugin\Gumshoe\Egress\Policy;
use Kanboard\Plugin\Gumshoe\Finding\BoardSync;
use Kanboard\Plugin\Gumshoe\Finding\Matcher;
use Kanboard\Plugin\Gumshoe\Finding\Reconciler;
use Kanboard\Plugin\Gumshoe\GitHub\RepoLister;
use Kanboard\Plugin\Gumshoe\GitHub\TreeReader;
use Kanboard\Plugin\Gumshoe\Http\Client;
use Kanboard\Plugin\Gumshoe\Http\HttpFailure;
use Kanboard\Plugin\Gumshoe\Http\Transport;
use Kanboard\Plugin\Gumshoe\Model\FindingModel;
use Kanboard\Plugin\Gumshoe\Model\InventoryStore;
use Kanboard\Plugin\Gumshoe\Model\RepoModel;
use Kanboard\Plugin\Gumshoe\Secrets\VaultTokenSource;
use Kanboard\Plugin\Gumshoe\Watch\WatchRules;
use PDO;
use PDOException;
use PDOStatement;
use Pimple\Container;
use Throwable;

/** A slice owns all request state, including the pagination bindings and Vault cache. */
final class ScanSlice
{
    private const TTL = 60;
    private const RETRY_DELAY = 60;

    private readonly WriterLease $lease;
    private readonly RunLog $log;
    private readonly string $holder;
    private readonly ScanTransport $transport;
    private readonly VaultTokenSource $tokens;
    private readonly Client $client;
    private readonly AdvisoryCache $cache;
    private readonly array $denyPrefixes;

    private array $run;
    private ?array $osvResults = null;
    private ?array $osvVersions = null;
    private bool $pendingFiltered = false;
    private bool $queryProgress = false;
    private ?array $malwareCatalog = null;
    private ?Policy $policy = null;

    public function __construct(
        private readonly PDO $pdo,
        private readonly Container $container,
        Transport $transport,
        string $applicationUrl,
        private readonly Closure $clock,
        private readonly ?int $deadline,
        private readonly array $settings,
        private readonly Closure $sleeper,
    ) {
        $this->lease = new WriterLease($pdo, $clock);
        $this->log = new RunLog($pdo);
        $this->holder = bin2hex(random_bytes(24));
        $this->transport = new ScanTransport($transport, $clock, $deadline, $this->keepLease(...));
        $this->tokens = new VaultTokenSource($container, $this->tokenRef(...), $clock);
        $this->client = new Client($this->transport, $applicationUrl, $this->tokens, $clock);
        $this->cache = new AdvisoryCache($pdo);
        $this->denyPrefixes = array_values(array_filter(array_map(
            trim(...),
            preg_split('/[\r\n,]+/', strtolower($settings['deny_prefixes'])),
        ), static fn (string $prefix): bool => $prefix !== ''));
    }

    public function run(string $job, string $trigger): array
    {
        $more = ['status' => 'more', 'summary' => 'The scan will continue on the next slice.'];
        $busy = ['status' => 'more', 'summary' => 'Another writer holds the scan lease.'];
        $claimed = false;
        $waitUntil = null;
        try {
            if (!$this->tokens->available() || $this->execute(
                "SELECT 1 FROM gumshoe_owners WHERE watch_id = 1 AND enabled = 1 AND token_ref <> '' LIMIT 1",
            )->fetchColumn() === false) {
                return ['status' => 'done', 'summary' => 'Scanning needs Vault Server sharing and an enabled owner with a token reference.'];
            }
            if ($this->deadline !== null && ($this->clock)() >= $this->deadline) {
                return $more;
            }
            if (!($claimed = $this->lease->claim($this->holder, self::TTL))) {
                $waitUntil = $this->deadline ?? PHP_INT_MAX;
                return $busy;
            }
            $active = $this->log->active();
            if ($active !== null && $active['job'] !== $job
                && !($active['job'] === Jobs::RECHECK && !(int) $this->settings['hourly'])) {
                $waitUntil = $this->deadline ?? PHP_INT_MAX;
                return $more;
            }
            $latest = $this->log->latest($job);
            $retryAt = (int) ($latest['retry_at'] ?? 0);
            if ($retryAt > ($this->clock)()) {
                $summary = 'waiting for retry at '.date('H:i', $retryAt);
                if ($latest['status'] === 'more') {
                    $waitUntil = $retryAt;
                    return ['status' => 'more', 'summary' => $summary];
                }
                return ['status' => 'done', 'summary' => $summary];
            }
            if (($latest['status'] ?? null) === 'more') {
                $this->run = $latest;
            } else {
                $this->run = $this->write(function () use ($job, $trigger): array {
                    $run = $this->log->start($job, $trigger, $job === Jobs::INVENTORY ? 'discover' : 'query', ($this->clock)());
                    if ($job === Jobs::RECHECK) {
                        $id = (int) $run['id'];
                        $this->enqueue($id, includeActions: false);
                        $this->log->checkpoint($id, 'query', $this->pendingPosition($id));
                        return $this->log->latest($job);
                    }
                    return $run;
                });
            }

            while ($this->deadline === null || ($this->clock)() < $this->deadline) {
                $this->transport->retryAt = null;
                $this->transport->completed = 0;
                $progress = match ($this->run['phase']) {
                    'discover' => $this->discover(),
                    'inventory' => $this->inventory(),
                    'query' => $this->query(),
                    'match' => $this->matchRepo(),
                    'sync' => $this->sync(),
                    'done' => false,
                };
                $this->run = $this->log->latest($job);
                if ($this->run['status'] === 'failed') {
                    return ['status' => 'failed', 'summary' => 'The scan failed. See the Gumshoe run log.'];
                }
                if ($this->run['status'] === 'ok') {
                    return ['status' => 'done', 'summary' => 'The scan completed.'];
                }
                if ($this->transport->stoppedOperation !== null && $this->recordStall()) {
                    return ['status' => 'failed', 'summary' => 'The scan failed. See the Gumshoe run log.'];
                }
                if (!$progress || (int) $this->run['retry_at'] > ($this->clock)()) {
                    break;
                }
            }
            return $more;
        } catch (LeaseLost) {
            return $more;
        } catch (Throwable $failure) {
            if (!$claimed && $failure instanceof PDOException && self::claimContended($failure)) {
                $waitUntil = $this->deadline ?? PHP_INT_MAX;
                return $busy;
            }
            if (!isset($this->run)) {
                return ['status' => 'failed', 'summary' => 'The scan could not start.'];
            }
            try {
                $failed = $this->write(function () use ($failure): bool {
                    $counts = $this->log->counts($this->id());
                    $number = ($counts['unexpected']['count'] ?? 0) + 1;
                    $counts['unexpected'] = ['count' => $number, 'class' => $failure::class];
                    $this->log->saveCounts($this->id(), $counts);
                    $retryAt = ($this->clock)() + self::RETRY_DELAY;
                    if ($number >= 3) {
                        $this->finish('failed', $failure::class, $retryAt);
                        return true;
                    }
                    $this->log->defer($this->id(), $retryAt);
                    return false;
                });
            } catch (LeaseLost) {
                return $more;
            }
            return $failed ? ['status' => 'failed', 'summary' => 'The scan failed. See the Gumshoe run log.'] : $more;
        } finally {
            $this->tokens->endSlice();
            if ($claimed) {
                $this->lease->release($this->holder);
            }
            if ($waitUntil !== null && $trigger === 'cli') {
                $now = ($this->clock)();
                $seconds = min(5, $waitUntil - $now, ($this->deadline ?? $waitUntil) - $now);
                if ($seconds > 0) {
                    ($this->sleeper)($seconds);
                }
            }
        }
    }

    private static function claimContended(PDOException $failure): bool
    {
        [$state, $code] = $failure->errorInfo ?? [null, null];
        return in_array($state, ['55P03', '40P01', '40001', '57014'], true)
            || ($state === 'HY000' && in_array((int) $code, [5, 6, 1205, 1213, 3572], true));
    }

    private function recordStall(): bool
    {
        $unit = [$this->run['phase'], $this->position()];
        return $this->write(function () use ($unit): bool {
            $counts = $this->log->counts($this->id());
            $prior = $counts['stalled'] ?? [];
            if (($prior['unit'] ?? null) !== $unit) {
                $prior = [];
            }
            $highWater = $prior['requests'] ?? 0;
            $completed = $this->transport->completed;
            // An interrupted unit may replay requests. Only fresh results or
            // reaching further than the previous slice count as progress.
            $progress = $this->queryProgress || $completed > $highWater;
            $slices = $progress ? 0 : ($prior['slices'] ?? 0) + 1;
            $counts['stalled'] = ['unit' => $unit, 'requests' => max($completed, $highWater), 'slices' => $slices];
            $this->log->saveCounts($this->id(), $counts);
            if ($slices < 3) {
                return false;
            }
            $this->finish('failed', HttpFailure::class, $this->retryTime(null));
            return true;
        });
    }

    private function discover(): bool
    {
        $owner = $this->execute('SELECT * FROM gumshoe_owners WHERE watch_id = 1 AND enabled = 1 AND id >= ? ORDER BY id LIMIT 1',
            [$this->position() ?? 1])->fetch(PDO::FETCH_ASSOC);
        if ($owner === false) {
            return $this->write(fn () => $this->advance('inventory'));
        }

        $id = (int) $owner['id'];
        $this->selectPosition($id);
        $listing = (new RepoLister($this->client))->list($owner, $this->run['job']);
        if ($this->transport->stopped) {
            return false;
        }

        $token = $this->tokens->status($owner['login']);
        $retryAt = $listing['retryAt'] ?? $token['retryAt'];
        $tokenUnavailable = $token['status'] === 'missing' || str_starts_with($token['status'], 'refused:');
        return $this->write(function () use ($owner, $listing, $id, $retryAt, $tokenUnavailable): bool {
            $this->saveTokenStatus($owner);
            if ($listing['status'] !== 'complete') {
                if (($retryAt !== null || !$tokenUnavailable) && $this->run['exception_class'] === null) {
                    return $this->backoff(HttpFailure::class, $retryAt);
                }
                $counts = $this->log->counts($this->id());
                $counts['failed_owners'][] = $id;
                $counts['owner_retry_at'] = max($counts['owner_retry_at'] ?? 0, $this->retryTime($retryAt));
                if (!$tokenUnavailable) {
                    $counts['listing_failed'] = true;
                }
                $this->log->saveCounts($this->id(), $counts);
            } else {
                (new RepoModel($this->pdo))->applyListing($id, $listing, ($this->clock)());
                $counts = $this->log->counts($this->id());
                $counts['listed_owners'][] = $id;
                $this->log->saveCounts($this->id(), $counts);
            }

            return $this->advance('discover', $id + 1, $listing['status'] === 'complete' ? $retryAt : null);
        });
    }

    private function inventory(): bool
    {
        $repo = $this->nextRepo();
        if ($repo === false) {
            return $this->write(function (): bool {
                $this->enqueue($this->id());
                $counts = $this->log->counts($this->id());
                if (!empty($counts['failed_owners']) && empty($counts['listed_owners'])) {
                    $this->finish('failed', HttpFailure::class, $counts['owner_retry_at']);
                    return false;
                }
                return $this->advance('query', $this->pendingPosition($this->id()));
            });
        }

        $id = (int) $repo['id'];
        $counts = $this->log->counts($this->id());
        if (in_array((int) $repo['owner_id'], $counts['failed_owners'] ?? [], true)) {
            return $this->write(fn () => $this->advance('inventory', $id + 1));
        }
        $this->selectPosition($id);
        $rules = new WatchRules($this->settings, ($this->clock)());
        $outcome = 'out_of_watch';
        $scan = null;
        if ($rules->watched($repo, $repo)) {
            $outcome = 'inaccessible';
            if (in_array((int) $repo['owner_id'], $counts['listed_owners'] ?? [], true)) {
                $store = new InventoryStore($this->pdo, $this->clock);
                $reuse = $store->filesForReuse($id);
                $files = array_filter($reuse['files'], static fn (array $file): bool =>
                    (int) $file['parser_version'] === TreeReader::PARSER_VERSION);
                $repo['inventoryReusable'] = $reuse['all'] && count($files) === count($reuse['files']);
                $state = $this->log->inventoryState($this->id(), $id);
                $slice = (new TreeReader($this->client))->readSlice(
                    $repo, $repo, $state, $this->run['job'], 1, $files,
                    fn (string $path, string $sha, int $version): ?array => $store->cachedRegistry($id, $path, $sha, $version),
                );
                if ($this->transport->stopped) {
                    return false;
                }
                if ($slice['state'] !== null) {
                    return $this->write(function () use ($id, $slice): bool {
                        $this->log->checkpointInventory($this->id(), $id, $slice['state'], $slice['files'], ($this->clock)());
                        $counts = $this->log->counts($this->id());
                        unset($counts['stalled']);
                        $this->log->saveCounts($this->id(), $counts);
                        $this->clearUnexpected();
                        $this->log->checkpoint($this->id(), 'inventory', $id, null, $this->run['exception_class']);
                        return true;
                    });
                }
                $scan = TreeReader::scan($slice['scan'], [...$this->log->inventoryFiles($this->id(), $id), ...$slice['files']]);
                $outcome = $scan['outcome'];
            }
        }

        return $this->write(function () use ($repo, $id, $scan, $outcome, $counts): bool {
            $this->log->clearInventory($this->id(), $id);
            if ($scan !== null) {
                $this->saveTokenStatus($repo);
                if ($scan['retryAt'] !== null && $outcome !== 'complete' && $outcome !== 'no_lockfile'
                    && $this->run['exception_class'] === null) {
                    return $this->backoff(HttpFailure::class, $scan['retryAt']);
                }
                if ($outcome !== 'inaccessible') {
                    $this->policy ??= $this->policy($counts['listed_owners']);
                    (new InventoryStore($this->pdo, $this->clock))->apply($this->id(), $id, $scan, $this->policy);
                }
            }
            // InventoryStore records complete/partial from file results. A
            // source's partial outcome also covers failed registry config reads.
            $this->execute('UPDATE gumshoe_repos SET outcome = ? WHERE id = ?', [$outcome, $id]);
            $counts[$outcome] = ($counts[$outcome] ?? 0) + 1;
            $this->log->saveCounts($this->id(), $counts);
            return $this->advance('inventory', $id + 1, $scan['retryAt'] ?? null);
        });
    }

    private function query(): bool
    {
        if (!$this->pendingFiltered) {
            if ($this->denyPrefixes !== [] || $this->run['job'] === Jobs::RECHECK) {
                $this->write($this->filterPending(...));
            }
            $this->pendingFiltered = true;
        }

        $osv = new Osv($this->client, $this->pdo, $this->clock);
        if (($position = $this->pendingPosition($this->id())) !== null) {
            $this->selectPosition($position);
            $rows = $osv->dueRows($this->id());
            if ($rows === []) {
                return $this->write(fn () => $this->backoff(HttpFailure::class, $osv->pendingRetryAt($this->id())));
            }

            $this->osvVersions ??= $osv->cachedVersions();
            $batch = $osv->fetch($rows, $this->osvVersions);
            if ($this->transport->stopped) {
                if ($batch['records'] !== []) {
                    // Retain validated details, but leave the interrupted
                    // queries pending without turning a deadline into a retry.
                    $this->write(fn () => $osv->store(array_replace($batch, ['ids' => []])));
                    $this->queryProgress = true;
                }
                return false;
            }

            return $this->write(function () use ($osv, $batch, $position): bool {
                $osv->store($batch);
                foreach ($batch['records'] as $id => $record) {
                    $this->osvVersions[$id] = $record['modified'];
                }
                if ($batch['retryAt'] !== null) {
                    return $this->sourceFailure($batch['retryAt'], $position);
                }
                return $this->advance('query', $this->pendingPosition($this->id()));
            });
        }
        if ($this->run['job'] === Jobs::RECHECK) {
            return $this->write(fn () => $this->advance('match'));
        }

        $saved = $this->log->malwareState($this->id());
        if ($saved === null || (isset($saved['seen']) && !$saved['done'])) {
            return $this->queryMalware($saved ?? ['seen' => []]);
        }

        $kev = new Kev($this->client, $this->cache);
        try {
            $catalog = $kev->fetch();
        } catch (HttpFailure) {
            return $this->transport->stopped ? false : $this->write(fn () => $this->sourceFailure($this->transport->retryAt));
        }
        return $this->write(function () use ($kev, $catalog): bool {
            $kev->store($catalog, ($this->clock)());
            return $this->advance('match');
        });
    }

    private function queryMalware(array $saved): bool
    {
        $github = new GithubMalware($this->client);
        $position = $this->position();
        try {
            $page = $github->fetchPage(is_string($position) ? $position : null, $saved['seen']);
        } catch (HttpFailure) {
            return $this->transport->stopped ? false : $this->write(fn () => $this->sourceFailure($this->transport->retryAt));
        }

        return $this->write(function () use ($github, $page, $saved): bool {
            $now = ($this->clock)();
            $this->log->checkpointMalware($this->id(), $saved, $page, $now);
            if ($page['next'] === null) {
                foreach ($this->log->malwarePages($this->id()) as $items) {
                    $github->store($items, $this->cache, $now);
                }
            }
            return $this->advance('query', $page['next']);
        });
    }

    private function matchRepo(): bool
    {
        $repo = $this->nextRepo();
        if ($repo === false) {
            return $this->write(fn () => $this->advance('sync'));
        }

        $runId = $this->id();
        $id = (int) $repo['id'];
        $inventory = $this->run['job'] === Jobs::INVENTORY;
        $counts = $this->log->counts($runId);
        if (in_array((int) $repo['owner_id'], $counts['failed_owners'] ?? [], true)) {
            return $this->write(fn () => $this->advance('match', $id + 1));
        }
        $pending = $this->rows(
            "SELECT DISTINCT p.* FROM gumshoe_pending p
             JOIN gumshoe_deps d ON p.query_type = d.query_type AND p.ecosystem = d.ecosystem
                AND p.name = d.name AND p.version = d.version
             JOIN gumshoe_lockfiles l ON l.id = d.lockfile_id
             WHERE p.run_id = ? AND l.repo_id = ? AND p.egress = 'public' AND d.egress = 'public'",
            [$runId, $id],
        );
        $this->osvResults ??= (new Osv($this->client, $this->pdo, $this->clock))->results($runId);
        $this->malwareCatalog ??= $inventory ? array_merge(...$this->log->malwarePages($runId)) : [];
        $catalog = $this->malwareCatalog;
        $github = new GithubMalware($this->client);
        $matches = [];
        $deps = [];
        if ((int) $repo['enabled'] && !in_array($repo['outcome'], ['inaccessible', 'out_of_watch'], true)) {
            $deps = $this->rows('SELECT d.*, l.repo_id FROM gumshoe_deps d
                JOIN gumshoe_lockfiles l ON l.id = d.lockfile_id WHERE l.repo_id = ? ORDER BY d.id', [$id]);
            foreach ($deps as &$dep) {
                if ($this->denied($dep['name'])) {
                    $dep['egress'] = 'denied';
                }
                $matches[$dep['id']] = $github->matches($catalog, $dep);
            }
            unset($dep);
        }

        return $this->write(function () use ($id, $repo, $inventory, $pending, $deps, $matches, $runId, $counts): bool {
            $result = (new Matcher(new GroupStore($this->pdo)))->exposures($deps, $pending, $this->osvResults, $matches);
            $transitions = (new Reconciler(new FindingModel($this->pdo)))->apply(
                $runId, $id, $inventory ? $repo['outcome'] : null, $result['exposures'], $inventory, ($this->clock)(),
            );
            $this->saveTransitions($transitions, $id);
            $counts['coverage_gaps'] = ($counts['coverage_gaps'] ?? 0) + ($result['coverage_gaps'][$id] ?? 0);
            $this->log->saveCounts($runId, $counts);
            return $this->advance('match', $id + 1);
        });
    }

    private function sync(): bool
    {
        // BoardSync processes absorbed tasks from the survivor, with the
        // survivor's full set of repo transitions available.
        $finding = $this->execute("SELECT id, group_id FROM gumshoe_findings
            WHERE id >= ? AND status <> 'merged' ORDER BY id LIMIT 1", [$this->position() ?? 1])->fetch(PDO::FETCH_ASSOC);
        if ($finding === false) {
            return $this->write(function (): bool {
                $counts = $this->log->counts($this->id());
                $failed = !empty($counts['listing_failed']);
                $this->advance('done');
                $this->finish($failed ? 'failed' : 'ok', $failed ? HttpFailure::class : null, $failed ? $counts['owner_retry_at'] : null);
                if (!$failed && $this->run['job'] === Jobs::INVENTORY) {
                    $this->log->purge(($this->clock)());
                }
                return false;
            });
        }

        $id = (int) $finding['id'];
        $this->selectPosition($id);
        return $this->write(function () use ($id, $finding): bool {
            $this->updateGroupPriority((int) $finding['group_id']);
            $transitions = $this->cache->get('run-transition', $this->id().':'.$id)['body'] ?? [];
            // A listener opening its own PicoDb transaction can closeTransaction() on this
            // shared connection and commit the fenced batch early. R5 recovery covers that.
            (new BoardSync($this->container))->sync($id, (int) $this->settings['project_id'], $this->id(), $transitions);
            return $this->advance('sync', $id + 1);
        });
    }

    private function updateGroupPriority(int $group): void
    {
        $aliases = $this->execute('SELECT alias FROM gumshoe_group_aliases WHERE group_id = ?', [$group])->fetchAll(PDO::FETCH_COLUMN);
        $kev = new Kev($this->client, $this->cache);
        $malware = false;
        $exploited = false;
        $score = null;
        foreach ($aliases as $alias) {
            $github = $this->cache->get('github-malware', $alias)['body'] ?? null;
            $osv = $this->cache->get('osv', $alias)['body'] ?? [];
            $malware = $malware || str_starts_with($alias, 'MAL-') || $github !== null;
            $exploited = $exploited || $kev->contains($alias);
            $scores = [$github['cvss']['score'] ?? null, $github['cvss_severities']['cvss_v4']['score'] ?? null];
            foreach (is_array($osv['severity'] ?? null) ? $osv['severity'] : [] as $severity) {
                if (($severity['type'] ?? null) === 'CVSS_V3' && is_string($severity['score'] ?? null)) {
                    $scores[] = self::cvssV3($severity['score']);
                }
            }
            foreach ($scores as $value) {
                if ((is_float($value) || is_int($value)) && $value >= 0 && $value <= 10) {
                    $score = max($value, $score ?? 0);
                }
            }
        }
        $old = $this->execute('SELECT cvss_max, malware, kev FROM gumshoe_groups WHERE id = ?', [$group])->fetch(PDO::FETCH_ASSOC);
        if ($old['cvss_max'] !== null) {
            $score = max($score ?? 0, (float) $old['cvss_max']);
        }
        $this->execute('UPDATE gumshoe_groups SET cvss_max = ?, malware = ?, kev = ? WHERE id = ?',
            [$score, (int) ($malware || $old['malware']), (int) ($exploited || $old['kev']), $group]);
    }

    /** OSV publishes CVSS v3 vectors, so calculate the base score from their required metrics. */
    private static function cvssV3(string $vector): ?float
    {
        if (!preg_match('~\ACVSS:3\.[01]/(?:[A-Z]{1,3}:[A-Z0-9]+/)*[A-Z]{1,3}:[A-Z0-9]+\z~', $vector)) {
            return null;
        }
        $metrics = [];
        foreach (array_slice(explode('/', $vector), 1) as $pair) {
            [$key, $value] = explode(':', $pair);
            if (isset($metrics[$key])) {
                return null;
            }
            $metrics[$key] = $value;
        }
        $scope = $metrics['S'] ?? null;
        if ($scope !== 'U' && $scope !== 'C') {
            return null;
        }
        $changed = $scope === 'C';
        $impact = ['H' => 0.56, 'L' => 0.22, 'N' => 0.0];
        $weights = [
            'AV' => ['N' => 0.85, 'A' => 0.62, 'L' => 0.55, 'P' => 0.2],
            'AC' => ['L' => 0.77, 'H' => 0.44],
            'PR' => ['N' => 0.85, 'L' => $changed ? 0.68 : 0.62, 'H' => $changed ? 0.5 : 0.27],
            'UI' => ['N' => 0.85, 'R' => 0.62],
            'C' => $impact, 'I' => $impact, 'A' => $impact,
        ];
        $values = [];
        foreach ($weights as $key => $valid) {
            $value = $valid[$metrics[$key] ?? ''] ?? null;
            if ($value === null) {
                return null;
            }
            $values[$key] = $value;
        }
        $subscore = 1 - (1 - $values['C']) * (1 - $values['I']) * (1 - $values['A']);
        $impactScore = $changed ? 7.52 * ($subscore - 0.029) - 3.25 * ($subscore - 0.02) ** 15 : 6.42 * $subscore;
        if ($impactScore <= 0) {
            return 0.0;
        }
        $exploitability = 8.22 * $values['AV'] * $values['AC'] * $values['PR'] * $values['UI'];
        $base = ($changed ? 1.08 : 1.0) * ($impactScore + $exploitability);
        return ceil(min(10, $base) * 10 - 1e-10) / 10;
    }

    private function enqueue(int $runId, bool $includeActions = true): void
    {
        $triples = $this->rows("SELECT DISTINCT query_type, ecosystem, name, version FROM gumshoe_deps WHERE egress = 'public'"
            .($includeActions ? '' : " AND ecosystem <> 'actions'"));
        $insert = $this->pdo->prepare(
            "INSERT INTO gumshoe_pending (run_id, query_type, ecosystem, name, version, egress) VALUES (?, ?, ?, ?, ?, 'public')"
        );
        foreach ($triples as $row) {
            if (!$this->denied($row['name'])) {
                $insert->execute([$runId, $row['query_type'], $row['ecosystem'], $row['name'], $row['version']]);
            }
        }
    }

    private function filterPending(): void
    {
        if ($this->run['job'] === Jobs::RECHECK) {
            $this->execute("UPDATE gumshoe_pending SET egress = 'unqueryable'
                WHERE run_id = ? AND egress = 'public' AND ecosystem = 'actions'", [$this->id()]);
        }
        if ($this->denyPrefixes === []) {
            return;
        }
        foreach ($this->rows("SELECT id, name FROM gumshoe_pending WHERE run_id = ? AND egress = 'public'", [$this->id()]) as $row) {
            if ($this->denied($row['name'])) {
                $this->execute("UPDATE gumshoe_pending SET egress = 'denied' WHERE id = ?", [$row['id']]);
            }
        }
    }

    private function denied(string $name): bool
    {
        foreach ($this->denyPrefixes as $prefix) {
            if (str_starts_with(strtolower($name), $prefix)) {
                return true;
            }
        }
        return false;
    }

    private function policy(array $listedOwners): Policy
    {
        $visibility = [];
        foreach ($this->rows('SELECT o.login, r.owner_id, r.name, r.private FROM gumshoe_repos r
            JOIN gumshoe_owners o ON o.id = r.owner_id WHERE o.enabled = 1 AND r.gone_at IS NULL') as $row) {
            if (in_array((int) $row['owner_id'], $listedOwners, true)) {
                $visibility[strtolower($row['login'].'/'.$row['name'])] = !(int) $row['private'];
            }
        }
        return new Policy($this->denyPrefixes, $visibility);
    }

    private function tokenRef(string $owner): ?string
    {
        $ref = $this->execute('SELECT token_ref FROM gumshoe_owners WHERE watch_id = 1 AND enabled = 1 AND LOWER(login) = ?',
            [$owner])->fetchColumn();
        return is_string($ref) ? $ref : null;
    }

    private function saveTokenStatus(array $owner): void
    {
        $token = $this->tokens->status($owner['login']);
        $status = str_starts_with($token['status'], 'refused:') ? 'refused' : $token['status'];
        $this->execute('UPDATE gumshoe_owners SET token_status = ?, token_expires_at = ? WHERE id = ?',
            [$status, $token['expiresAt'], $owner['owner_id'] ?? $owner['id']]);
    }

    private function saveTransitions(array $transitions, int $repo): void
    {
        foreach ($transitions as $id => $transition) {
            if ($transition['to'] === 'merged') {
                // The group and finding rows already persist the merge.
                continue;
            }
            $key = $this->id().':'.$id;
            $rows = $this->cache->get('run-transition', $key)['body'] ?? [];
            $rows[$repo] = $transition;
            $this->cache->put('run-transition', $key, $rows, null, ($this->clock)());
        }
    }

    private function selectPosition(int $id): void
    {
        if ($this->position() !== $id) {
            $this->write(fn () => $this->advance($this->run['phase'], $id));
            $this->run = $this->log->latest($this->run['job']);
        }
    }

    private function backoff(string $error, ?int $retryAt = null, int|string|null $position = null): bool
    {
        $this->clearUnexpected();
        $this->log->checkpoint($this->id(), $this->run['phase'], $position ?? $this->position(),
            $this->retryTime($retryAt), $error);
        return false;
    }

    private function retryTime(?int $retryAt): int
    {
        $now = ($this->clock)();
        return max($now + 1, $retryAt ?? $now + self::RETRY_DELAY);
    }

    private function sourceFailure(?int $retryAt, int|string|null $position = null): bool
    {
        if ($this->run['exception_class'] !== null && ($position === null || $position === $this->position())) {
            $this->finish('failed', HttpFailure::class, $this->retryTime($retryAt));
            return false;
        }
        return $this->backoff(HttpFailure::class, $retryAt, $position);
    }

    private function finish(string $status, ?string $error = null, ?int $retryAt = null): void
    {
        $this->execute("DELETE FROM gumshoe_advisory_cache WHERE source = 'run-transition' AND advisory_id LIKE ?",
            [$this->id().':%']);
        $this->log->clearMalware($this->id());
        $this->log->clearInventory($this->id());
        $this->log->finish($this->id(), $status, ($this->clock)(), $error, $retryAt);
    }

    private function advance(string $phase, int|string|null $position = null, ?int $retryAt = null): bool
    {
        $this->clearUnexpected();
        $this->log->checkpoint($this->id(), $phase, $position, $retryAt);
        return true;
    }

    private function clearUnexpected(): void
    {
        $counts = $this->log->counts($this->id());
        if (isset($counts['unexpected'])) {
            unset($counts['unexpected']);
            $this->log->saveCounts($this->id(), $counts);
        }
    }

    private function nextRepo(): array|false
    {
        return $this->execute('SELECT r.*, o.login, o.enabled FROM gumshoe_repos r
            JOIN gumshoe_owners o ON o.id = r.owner_id WHERE o.watch_id = 1 AND r.id >= ? ORDER BY r.id LIMIT 1',
            [$this->position() ?? 1])->fetch(PDO::FETCH_ASSOC);
    }

    private function pendingPosition(int $runId): ?int
    {
        $id = $this->execute("SELECT MIN(id) FROM gumshoe_pending WHERE run_id = ? AND egress = 'public' AND state = 'pending'",
            [$runId])->fetchColumn();
        return $id === null ? null : (int) $id;
    }

    private function position(): int|string|null
    {
        $position = $this->run['position'];
        return $position !== null && ctype_digit((string) $position) ? (int) $position : $position;
    }

    private function id(): int
    {
        return (int) $this->run['id'];
    }

    private function keepLease(): bool
    {
        return $this->lease->renew($this->holder, self::TTL);
    }

    private function write(callable $batch): mixed
    {
        if (!$this->keepLease()) {
            throw new LeaseLost();
        }
        return $this->lease->write($this->holder, $batch);
    }

    private function rows(string $sql, array $parameters = []): array
    {
        return $this->execute($sql, $parameters)->fetchAll(PDO::FETCH_ASSOC);
    }

    private function execute(string $sql, array $parameters = []): PDOStatement
    {
        $statement = $this->pdo->prepare($sql);
        $statement->execute($parameters);
        return $statement;
    }
}
