<?php

namespace Kanboard\Plugin\Gumshoe\Run;

use Closure;
use InvalidArgumentException;
use Kanboard\Plugin\Gumshoe\Http\CurlTransport;
use Kanboard\Plugin\Gumshoe\Http\Transport;
use Kanboard\Plugin\Gumshoe\Model\SettingsModel;
use Pimple\Container;

final readonly class Scanner
{
    private Closure $clock;

    public function __construct(
        private Container $container,
        private Transport $transport = new CurlTransport(),
        private ?string $applicationUrl = null,
        ?Closure $clock = null,
    ) {
        $this->clock = $clock ?? time(...);
    }

    /** Advance one job until it completes, backs off, or reaches the absolute Unix deadline. */
    public function tick(string $job, string $trigger, ?int $deadline = null): array
    {
        if (!isset(Jobs::INTERVALS[$job]) || !in_array($trigger, ['cli', 'foreman', 'visit'], true)) {
            throw new InvalidArgumentException('Unknown Gumshoe job or trigger.');
        }

        $pdo = $this->container['db']->getConnection();
        $settings = (new SettingsModel($pdo))->get();
        if (!(int) $settings['scanning'] || ($job === Jobs::RECHECK && !(int) $settings['hourly'])) {
            return ['status' => 'done', 'summary' => 'Scanning is disabled for this job.'];
        }
        if ($deadline !== null && ($this->clock)() >= $deadline) {
            return ['status' => 'more', 'summary' => 'The scan will continue on the next slice.'];
        }

        $url = $this->applicationUrl ?? ($this->container['configModel']->get('application_url') ?: 'http://localhost/');
        return (new ScanSlice($pdo, $this->container, $this->transport, $url, $this->clock, $deadline, $settings))
            ->run($job, $trigger);
    }
}
