<?php

namespace Kanboard\Plugin\Gumshoe;

use Kanboard\Core\Plugin\Base;
use Kanboard\Plugin\Gumshoe\Console\ScanCommand;
use Kanboard\Plugin\Gumshoe\Run\Jobs;
use Kanboard\Plugin\Gumshoe\Run\Scanner;
use Kanboard\Plugin\Gumshoe\Run\VisitTrigger;

class Plugin extends Base
{
    public function initialize(): void
    {
        require_once __DIR__.'/vendor/autoload.php';

        $container = $this->container;
        $container['gumshoeScanner'] ??= static fn ($c) => new Scanner($c);
        $container['gumshoeVisitTrigger'] ??= static fn ($c) => new VisitTrigger($c);
        $container['cli']->add(new ScanCommand($container));

        $this->hook->on('foreman:jobs', static function () use ($container): array {
            $jobs = (new Jobs($container['gumshoeScanner']))->descriptors();
            foreach ($jobs as &$job) {
                $job['title'] = $job['id'] === Jobs::INVENTORY ? 'Gumshoe inventory scan' : 'Gumshoe OSV recheck';
            }
            return $jobs;
        });
        $this->hook->on('template:layout:top', [
            'template' => 'Gumshoe:layout/visit_trigger',
            'callable' => static function () use ($container): array {
                $container['gumshoeVisitTrigger']->schedule();
                return [];
            },
        ]);
    }

    public function getPluginName(): string
    {
        return 'Gumshoe';
    }

    public function getPluginDescription(): string
    {
        return 'Watch GitHub lockfiles for vulnerable dependencies and malware, and track findings in Kanboard.';
    }

    public function getPluginAuthor(): string
    {
        return 'Carmelo Santana';
    }

    public function getPluginVersion(): string
    {
        return '1.0.0';
    }

    public function getPluginHomepage(): string
    {
        return 'https://github.com/carmelosantana/kanboard-gumshoe';
    }

    public function getPluginLicense(): string
    {
        return 'MIT';
    }

    public function getCompatibleVersion(): string
    {
        return '>=1.2.47';
    }
}
