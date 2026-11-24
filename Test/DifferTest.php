<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Inventory\Differ;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class DifferTest extends TestCase
{
    public function testSingleVersionChange(): void
    {
        self::assertSame(
            [$this->change('changed', '4.0.0', '4.0.1')],
            Differ::diff([$this->row('4.0.0')], [$this->row('4.0.1')]),
        );
    }

    public function testDroppingOneVersionKeepsTheOther(): void
    {
        self::assertSame(
            [$this->change('removed', '3.0.0', null)],
            Differ::diff([$this->row('3.0.0'), $this->row('4.0.0')], [$this->row('4.0.0')]),
        );
    }

    public function testDuplicateInstallsAndScopeChangesDoNotChangeTheVersionSet(): void
    {
        $rows = [$this->row('4.0.0'), $this->row('4.0.0'), $this->row('4.0.0', scope: 'dev')];
        self::assertSame([], Differ::diff($rows, [$this->row('4.0.0')]));
        self::assertSame([], Differ::diff([$this->row('4.0.0')], $rows));
    }

    public function testMovingBetweenLockfilesIsARemovalAndAnAddition(): void
    {
        self::assertSame(
            [
                $this->change('removed', '4.0.0', null),
                $this->change('added', null, '4.0.0', 'tools/package-lock.json'),
            ],
            Differ::diff([$this->row('4.0.0')], [$this->row('4.0.0', 'tools/package-lock.json')]),
        );
    }

    public function testAmbiguousVersionChangesAreReportedIndividually(): void
    {
        self::assertSame(
            [
                $this->change('removed', '3.0.0', null),
                $this->change('removed', '4.0.0', null),
                $this->change('added', null, '4.0.1'),
            ],
            Differ::diff([$this->row('3.0.0'), $this->row('4.0.0')], [$this->row('4.0.1')]),
        );
    }

    private function row(string $version, string $path = 'package-lock.json', string $scope = 'prod'): array
    {
        return ['ecosystem' => 'npm', 'name' => 'universal-user-agent', 'path' => $path, 'version' => $version, 'scope' => $scope];
    }

    private function change(string $kind, ?string $from, ?string $to, string $path = 'package-lock.json'): array
    {
        return [
            'kind' => $kind, 'ecosystem' => 'npm', 'name' => 'universal-user-agent', 'path' => $path,
            'from_version' => $from, 'to_version' => $to,
        ];
    }
}
