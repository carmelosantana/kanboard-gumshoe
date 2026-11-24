<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Advisory\VersionRange;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class VersionRangeTest extends TestCase
{
    /** @dataProvider cases */
    public function testRange(bool $expected, string $ecosystem, string $version, string $range): void
    {
        self::assertSame($expected, VersionRange::matches($ecosystem, $version, $range));
    }

    public static function cases(): iterable
    {
        yield 'equals' => [true, 'npm', '1.0.0', '= 1.0.0'];
        yield 'equals fails' => [false, 'npm', '1.0.1', '= 1.0.0'];
        yield 'less than' => [true, 'npm', '1.0.0-beta', '< 1.0.0'];
        yield 'less than excludes boundary' => [false, 'npm', '1.0.0', '< 1.0.0'];
        yield 'less than or equal' => [true, 'npm', '1.0.0', '<= 1.0.0'];
        yield 'less than or equal excludes later' => [false, 'npm', '1.0.1', '<= 1.0.0'];
        yield 'greater than' => [true, 'npm', '1.0.1', '> 1.0.0'];
        yield 'greater than excludes boundary' => [false, 'npm', '1.0.0', '> 1.0.0'];
        yield 'greater than or equal' => [true, 'npm', '1.0.0', '>= 1.0.0'];
        yield 'greater than or equal excludes earlier' => [false, 'npm', '1.0.0-beta', '>= 1.0.0'];
        yield 'conjunction' => [true, 'npm', '1.0.1', '> 1.0.0, <= 1.0.1'];
        yield 'conjunction checks upper limit' => [false, 'npm', '1.0.2', '> 1.0.0, <= 1.0.1'];
        yield 'numeric prerelease identifiers' => [true, 'npm', '1.0.0-beta.9', '< 1.0.0-beta.10'];
        yield 'numeric identifiers sort before letters' => [true, 'npm', '1.0.0-9', '< 1.0.0-alpha'];
        yield 'prerelease prefixes sort first' => [true, 'npm', '1.0.0-alpha', '< 1.0.0-alpha.1'];
        yield 'real GitHub shorthand' => [true, 'npm', '1.0.0', '>= 0'];
        yield 'inclusive partial upper boundary' => [true, 'npm', '1.9.0', '<= 1'];
        yield 'exclusive partial lower boundary' => [false, 'npm', '1.9.0', '> 1'];
        yield 'build metadata ignored' => [true, 'npm', '1.0.0+build.123', '= 1.0.0'];
        yield 'composer normalized' => [true, 'composer', 'v1.2', '= 1.2.0.0'];
        yield 'composer branch' => [false, 'composer', 'dev-main', '< 1.2.0.0'];
        yield 'composer suffixes' => [true, 'composer', 'v1.2.0-RC1', '< 1.2.0.0'];
        yield 'unsupported expression' => [false, 'npm', '1.0.0', '>= 1.0.0, ^2.0.0'];
        yield 'not a semver' => [false, 'npm', '01.0.0', '= 1.0.0'];
    }
}
