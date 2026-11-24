<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Plugin\Gumshoe\Inventory\Dependency;
use Kanboard\Plugin\Gumshoe\Inventory\Limits;
use Kanboard\Plugin\Gumshoe\Inventory\Workflows;
use PHPUnit\Framework\TestCase;

require_once __DIR__.'/bootstrap.php';

final class WorkflowsTest extends TestCase
{
    public function testReadsStepActionsAndReusableWorkflowJobs(): void
    {
        $result = Workflows::parse(file_get_contents(__DIR__.'/fixtures/lockfiles/workflow-mixed.hand.yml'), new Limits());

        self::assertSame('ok', $result->status);
        self::assertEquals([
            new Dependency('actions', 'actions/checkout', 'b4ffde65f46336ab88eb53be808477a3936bae11', 'action', null, 'commit', null),
            new Dependency('actions', 'actions/setup-node', 'v4', 'action', 'mutable', 'none', null),
            new Dependency('actions', 'github/codeql-action', 'v4', 'action', 'mutable', 'none', null),
            new Dependency('docker', 'rhysd/actionlint:1.7.7', null, 'action', null, 'none', null),
            new Dependency('actions', 'slsa-framework/slsa-github-generator', 'v2.0.0', 'action', 'mutable', 'none', null),
        ], $result->deps);
    }

    public function testCanonicalizesCaseAndDoesNotReadUsesFromOtherFields(): void
    {
        $result = Workflows::parse(<<<'YAML'
            uses: actions/checkout@v4
            jobs:
              build:
                steps:
                  - uses: GitHub/CodeQL-Action/init@B4FFDE65F46336AB88EB53BE808477A3936BAE11
                  - uses: actions/checkout@release/v4
                  - run: |
                      uses: actions/checkout@v3
                    with:
                      uses: actions/checkout@v2
              local:
                uses: ./.github/workflows/local.yml
            YAML, new Limits());

        self::assertSame('ok', $result->status);
        self::assertSame(['github/codeql-action', 'actions/checkout'], array_column($result->deps, 'name'));
        self::assertSame(['b4ffde65f46336ab88eb53be808477a3936bae11', 'release/v4'], array_column($result->deps, 'version'));
        self::assertSame(['commit', 'none'], array_column($result->deps, 'query_type'));
    }

    public function testFileAndRepoCapsReturnNoRows(): void
    {
        $result = Workflows::parse(str_repeat(' ', Limits::MAX_FILE_BYTES + 1), new Limits());
        self::assertSame('too_large', $result->status);
        self::assertSame([], $result->deps);

        $contents = file_get_contents(__DIR__.'/fixtures/lockfiles/workflow-mixed.hand.yml');
        $result = Workflows::parse($contents, new Limits(Limits::MAX_REPO_DEPS - 4));
        self::assertSame('too_many', $result->status);
        self::assertSame([], $result->deps);
    }
}
