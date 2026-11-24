<?php

namespace Kanboard\Plugin\Gumshoe\Console;

use Kanboard\Console\BaseCommand;
use Kanboard\Plugin\Gumshoe\Run\Jobs;
use Kanboard\Plugin\Gumshoe\Run\RunLog;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

final class ScanCommand extends BaseCommand
{
    protected function configure(): void
    {
        $this->setName('gumshoe:scan')
            ->setDescription('Run due Gumshoe jobs')
            ->addOption('job', null, InputOption::VALUE_REQUIRED, 'Run one Gumshoe job by ID');
    }

    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $onlyJob = $input->getOption('job');
        if ($onlyJob !== null && !isset(Jobs::INTERVALS[$onlyJob])) {
            $output->writeln('<error>Unknown Gumshoe job.</error>');
            return self::INVALID;
        }

        $log = new RunLog($this->db->getConnection());
        if ($onlyJob !== null) {
            return $this->runJob($onlyJob, $log, $output);
        }

        $exit = self::SUCCESS;
        $attempted = [];
        $schedule = $this->container['gumshoeVisitTrigger'];
        while ($jobs = array_diff($schedule->dueJobs(), $attempted)) {
            $job = reset($jobs);
            $attempted[] = $job;
            $exit = max($exit, $this->runJob($job, $log, $output));
        }
        return $exit;
    }

    private function runJob(string $job, RunLog $log, OutputInterface $output): int
    {
        $scanner = $this->container['gumshoeScanner'];
        while (true) {
            $result = $scanner->tick($job, 'cli');
            $output->writeln($job.' '.$result['summary'], OutputInterface::OUTPUT_RAW);
            if ($result['status'] !== 'more') {
                return $result['status'] === 'failed' ? self::FAILURE : self::SUCCESS;
            }

            $active = $log->active();
            if ($active === null) {
                return self::SUCCESS;
            }
            if ($active['job'] !== $job) {
                $output->writeln('<error>Resume the other Gumshoe job before running this job.</error>');
                return self::FAILURE;
            }

            // An unbounded scan can still pause for an advisory or Vault retry.
            // Give up the lease between slices and check the persisted retry time.
            do {
                $remaining = (int) ($active['retry_at'] ?? 0) - time();
                sleep(max(1, min(60, $remaining)));
                $active = $log->latest($job);
            } while ($active !== null && $active['status'] === 'more' && (int) $active['retry_at'] > time());

            if (($active['status'] ?? null) === 'ok') {
                return self::SUCCESS;
            }
            if (($active['status'] ?? null) === 'failed') {
                return self::FAILURE;
            }
        }
    }
}
