<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Advisory\Priority;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class PriorityTest extends TestCase
{
    /** @dataProvider severityCases */
    public function testPriority(string $expected, array $group): void
    {
        self::assertSame($expected, Priority::of($group));
    }

    public static function severityCases(): iterable
    {
        yield 'malware overrides low score' => ['urgent', ['malware' => true, 'cvss_max' => 1.0]];
        yield 'KEV overrides missing score' => ['urgent', ['kev' => true]];
        yield 'high threshold' => ['high', ['cvss_max' => 7.0]];
        yield 'development scope keeps high priority' => ['high', ['cvss_max' => 9.0, 'scope' => 'dev']];
        yield 'just below high' => ['normal', ['cvss_max' => 6.9]];
        yield 'normal threshold' => ['normal', ['cvss_max' => 4.0]];
        yield 'unknown' => ['normal', ['cvss_max' => null]];
        yield 'just below normal' => ['low', ['cvss_max' => 3.9]];
        yield 'zero score' => ['low', ['cvss_max' => 0.0, 'kev' => 0, 'malware' => 0]];
    }

    /** @dataProvider projectRanges */
    public function testProjectPriorityMapping(int $start, int $end, array $expected): void
    {
        self::assertSame($expected, array_map(
            static fn (string $priority): int => Priority::toProject($priority, $start, $end),
            ['low', 'normal', 'high', 'urgent'],
        ));
    }

    public static function projectRanges(): iterable
    {
        yield 'core range' => [0, 3, [0, 1, 2, 3]];
        yield 'custom range' => [1, 5, [1, 2, 4, 5]];
        yield 'single priority' => [2, 2, [2, 2, 2, 2]];
    }
}
