<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Plugin;
use PHPUnit\Framework\TestCase;
use Pimple\Container;

require_once __DIR__.'/bootstrap.php';

class PluginTest extends TestCase
{
    public function testVersionsAgree(): void
    {
        $plugin = new Plugin(new Container());

        $this->assertSame('1.0.0', $this->manifest()['version']);
        $this->assertSame('1.0.0', $plugin->getPluginVersion());
    }

    public function testDependencies(): void
    {
        $manifest = $this->manifest();

        $this->assertCount(1, $manifest['requires']);
        $vault = $manifest['requires'][0];
        $this->assertSame('Vault', $vault['plugin']);
        $this->assertMatchesRegularExpression('/^\d+\.\d+\.\d+$/D', $vault['min_version']);
        $this->assertNotSame('', trim($vault['reason']));

        $this->assertCount(2, $manifest['recommends']);
        $this->assertSame(['Foreman', 'Harbor'], array_column($manifest['recommends'], 'plugin'));
    }

    private function manifest(): array
    {
        return json_decode(file_get_contents(__DIR__.'/../plugin.json'), true, flags: JSON_THROW_ON_ERROR);
    }
}
