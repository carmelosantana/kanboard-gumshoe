<?php

namespace Kanboard\Plugin\Gumshoe;

use Kanboard\Core\Plugin\Base;

class Plugin extends Base
{
    public function initialize(): void
    {
        require_once __DIR__.'/vendor/autoload.php';
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
