<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Watch\WatchRules;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class WatchRulesTest extends TestCase
{
    public function testReasonsAndWatchPrecedence(): void
    {
        $now = 1_800_000_000;
        $settings = ['window_days' => 90, 'forks' => 0, 'archived' => 0];
        $repo = ['mode' => 'auto', 'fork' => 0, 'archived' => 0, 'pushed_at' => $now - 90 * 86400, 'gone_at' => null];
        $rules = new WatchRules($settings, $now);
        foreach ([
            [0, ['mode' => 'pin'], false, 'owner off'],
            [0, ['mode' => 'exclude'], false, 'owner off'],
            [1, ['mode' => 'exclude'], false, 'excluded'],
            [1, ['mode' => 'pin', 'fork' => 1, 'archived' => 1, 'pushed_at' => null], true, 'pinned'],
            [1, ['fork' => 1, 'archived' => 1], false, 'fork'],
            [1, ['archived' => 1], false, 'archived'],
            [1, [], true, 'pushed 90d ago'],
            [1, ['pushed_at' => $now - 91 * 86400], false, 'idle 91d'],
        ] as [$enabled, $changes, $watched, $reason]) {
            $owner = ['enabled' => $enabled];
            self::assertSame($reason, $rules->reason($owner, $changes + $repo));
            self::assertSame($watched, $rules->watched($owner, $changes + $repo));
        }

        $rules = new WatchRules(['window_days' => 91, 'forks' => 1, 'archived' => 1], $now);
        self::assertTrue($rules->watched(['enabled' => 1], [
            'fork' => 1, 'archived' => 1, 'pushed_at' => $now - 91 * 86400,
        ] + $repo));
        self::assertFalse($rules->watched(['enabled' => 1], ['gone_at' => $now, 'mode' => 'pin'] + $repo));
    }
}
