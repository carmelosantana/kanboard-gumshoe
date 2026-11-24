<?php

namespace Kanboard\Plugin\Gumshoe\Run;

use Closure;
use Kanboard\Plugin\Gumshoe\Model\SettingsModel;
use Pimple\Container;
use Throwable;

final class VisitTrigger
{
    private readonly Closure $clock;
    private readonly Closure $registerShutdown;
    private readonly Closure $closeSession;
    private readonly ?Closure $finishResponse;
    private bool $scheduled = false;

    public function __construct(
        private readonly Container $container,
        ?Closure $clock = null,
        ?Closure $registerShutdown = null,
        ?Closure $closeSession = null,
        ?Closure $finishResponse = null,
    ) {
        $this->clock = $clock ?? time(...);
        $this->registerShutdown = $registerShutdown ?? register_shutdown_function(...);
        $this->closeSession = $closeSession ?? session_write_close(...);
        $this->finishResponse = $finishResponse
            ?? (function_exists('fastcgi_finish_request') ? fastcgi_finish_request(...) : null);
    }

    public function schedule(): void
    {
        if ($this->scheduled || $this->finishResponse === null) {
            return;
        }

        try {
            if ($this->nextVisitJob() !== null) {
                ($this->registerShutdown)($this->afterResponse(...));
                $this->scheduled = true;
            }
        } catch (Throwable $error) {
            $this->logFailure($error);
        }
    }

    /** Jobs eligible for the local schedule, shared by page visits and the CLI. */
    public function dueJobs(): array
    {
        $pdo = $this->container['db']->getConnection();
        $settings = (new SettingsModel($pdo))->get();
        if (!(int) $settings['scanning']) {
            return [];
        }

        $intervals = Jobs::INTERVALS;
        if (!(int) $settings['hourly']) {
            unset($intervals[Jobs::RECHECK]);
        }

        $now = ($this->clock)();
        $log = new RunLog($pdo);
        $active = $log->active();
        if (isset($intervals[$active['job'] ?? ''])) {
            // Scanner resumes the active job before allowing another one to start.
            return (int) $active['retry_at'] <= $now ? [$active['job']] : [];
        }

        $due = [];
        foreach ($intervals as $job => $interval) {
            $last = $log->latest($job);
            if ($last === null || max((int) $last['finished_at'] + $interval, (int) $last['retry_at']) <= $now) {
                $due[] = $job;
            }
        }
        return $due;
    }

    private function nextVisitJob(): ?string
    {
        if (isset($this->container['foreman']) || !$this->container['userSession']->isLogged()) {
            return null;
        }
        $pdo = $this->container['db']->getConnection();
        // This read avoids scheduling needless work. Scanner still claims the writer lease atomically.
        $leaseUntil = $pdo->query("SELECT lease_until FROM gumshoe_state WHERE name = 'writer'")->fetchColumn();
        if ($leaseUntil === false || (int) $leaseUntil >= ($this->clock)()) {
            return null;
        }
        return $this->dueJobs()[0] ?? null;
    }

    private function afterResponse(): void
    {
        try {
            $job = $this->nextVisitJob();
            if ($job === null) {
                return;
            }
            ($this->closeSession)();
            if (($this->finishResponse)()) {
                $this->container['gumshoeScanner']->tick($job, 'visit', ($this->clock)() + Jobs::BUDGET);
            }
        } catch (Throwable $error) {
            $this->logFailure($error);
        }
    }

    private function logFailure(Throwable $error): void
    {
        $this->container['logger']->error('Gumshoe visit trigger failed ('.$error::class.').');
    }
}
