<?php

namespace Kanboard\Plugin\Gumshoe\Test;

use Kanboard\Model\CommentModel;
use Kanboard\Model\SubtaskModel;
use Kanboard\Model\TaskCreationModel;
use Kanboard\Model\TaskFinderModel;
use Kanboard\Model\TaskStatusModel;
use Kanboard\Plugin\Gumshoe\Finding\BoardSync;
use Kanboard\Plugin\Gumshoe\Model\FindingModel;
use KanboardTests\units\Base;
use PDO;
use RuntimeException;

use function Kanboard\Plugin\Gumshoe\Schema\version_1;

require_once 'tests/units/Base.php';
require_once __DIR__.'/ReleasesConnection.php';

final class BoardSyncTest extends Base
{
    use ReleasesConnection;

    protected PDO $pdo;
    private int $project;

    protected function setUp(): void
    {
        parent::setUp();
        require_once __DIR__.'/../Schema/'.ucfirst(DB_DRIVER).'.php';
        $this->pdo = $this->container['db']->getConnection();
        version_1($this->pdo);
        $this->project = $this->container['projectModel']->create(['name' => 'Findings', 'priority_start' => 2, 'priority_end' => 8]);
        $this->pdo->exec(<<<'SQL'
            INSERT INTO gumshoe_owners (id, login, kind) VALUES (1, 'symfony', 'org');
            INSERT INTO gumshoe_repos (id, owner_id, name, github_id) VALUES (1, 1, 'yaml', 1), (2, 1, 'console', 2);
            INSERT INTO gumshoe_groups (id, primary_id) VALUES (1, 'CVE-2018-16492'), (2, 'GHSA-mh6f-8j2x-4483');
            INSERT INTO gumshoe_findings (group_id, ecosystem, package) VALUES (1, 'npm', 'flatmap-stream');
            INSERT INTO gumshoe_finding_repos (finding_id, repo_id, state, ever_affected) VALUES (1, 1, 'affected', 1);
            SQL);
        $trigger = DB_DRIVER === 'mysql' ? '`trigger`' : '"trigger"';
        $this->pdo->exec("INSERT INTO gumshoe_runs (id, job, $trigger, started_at) VALUES (1, 'gumshoe.inventory', 'cli', 1)");
    }

    public function testRecoversTaskAndSubtaskInsertedBeforeInterruption(): void
    {
        $interrupt = true;
        $this->container['hook']->on('model:task:creation:aftersave', static function () use (&$interrupt) {
            if ($interrupt) {
                throw new RuntimeException('Task interrupted');
            }
        });
        $subtask = new class($this->container) extends SubtaskModel {
            public bool $interrupt = true;

            public function create(array $values)
            {
                $id = parent::create($values);
                if ($this->interrupt && $id) {
                    $this->interrupt = false;
                    throw new RuntimeException('Subtask interrupted');
                }

                return $id;
            }
        };
        $this->container['subtaskModel'] = $subtask;
        $this->assertInterrupted('Task interrupted');
        self::assertSame(0, (int) $this->finding()['task_id']);
        $task = $this->container['taskFinderModel']->getByReference($this->project, 'gumshoe:finding:1');
        self::assertNotEmpty($task);

        $interrupt = false;
        $this->assertInterrupted('Subtask interrupted');
        $id = (int) $task['id'];
        self::assertCount(1, $this->container['subtaskModel']->getAll($id));
        $this->sync();
        $this->sync();
        self::assertSame($id, (int) $this->finding()['task_id']);
        self::assertSame('[Gumshoe] flatmap-stream — CVE-2018-16492 (1 repo)', $task['title']);
        self::assertSame(4, (int) $task['priority']);
        self::assertSame(['symfony/yaml'], array_column($this->container['subtaskModel']->getAll($id), 'title'));
        self::assertSame(1, $this->container['taskFinderModel']->countByProjectId($this->project));
    }

    public function testFalseCoreCreateFails(): void
    {
        $this->container['taskCreationModel'] = new class($this->container) extends TaskCreationModel {
            public function create(array $values)
            {
                return false;
            }
        };

        $this->expectException(RuntimeException::class);
        $this->expectExceptionMessage('Gumshoe could not create task.');
        $this->sync();
    }

    public function testFalseSubtaskCreateFails(): void
    {
        $this->container['subtaskModel'] = new class($this->container) extends SubtaskModel {
            public function create(array $values)
            {
                return false;
            }
        };

        $this->assertInterrupted('Gumshoe could not create subtask.');
        $this->container['subtaskModel'] = new SubtaskModel($this->container);
        $this->sync();
        self::assertCount(1, $this->container['subtaskModel']->getAll((int) $this->finding()['task_id']));
        self::assertSame(1, $this->container['taskFinderModel']->countByProjectId($this->project));
    }

    public function testFalseCommentCreateRollsBackFix(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'fixed'");
        $this->container['commentModel'] = new class($this->container) extends CommentModel {
            public function create(array $values)
            {
                return false;
            }
        };

        $this->assertInterrupted('Gumshoe could not create comment.');
        self::assertTrue($this->container['taskStatusModel']->isOpen($id));
        self::assertSame([SubtaskModel::STATUS_TODO], $this->subtaskStatuses($id));
    }

    public function testFalseTaskCloseRollsBackFix(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'fixed'");
        $this->container['taskStatusModel'] = new class($this->container) extends TaskStatusModel {
            public function close($task_id)
            {
                return false;
            }
        };

        $this->assertInterrupted('Gumshoe could not close task.');
        self::assertSame([], $this->comments($id));
        self::assertSame([SubtaskModel::STATUS_TODO], $this->subtaskStatuses($id));
    }

    public function testPersonCanReopenFixedTaskAndNewEvidenceResetsTheOverride(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'fixed'");
        $this->sync();
        self::assertTrue($this->container['taskStatusModel']->open($id));
        $this->sync();
        $this->sync(1, [1 => ['to' => 'fixed']]);
        self::assertTrue($this->container['taskStatusModel']->isOpen($id));
        self::assertSame('fixed', $this->finding()['status']);
        self::assertGreaterThan(0, (int) $this->finding()['reopened_by_person_at']);
        self::assertSame(['Fixed in symfony/yaml.', 'Fixed in all repos.'], $this->comments($id));

        $reopened = $this->finding()['reopened_by_person_at'];
        $this->pdo->exec('UPDATE gumshoe_groups SET cvss_max = 8 WHERE id = 1');
        $this->sync();
        self::assertTrue($this->container['taskStatusModel']->isOpen($id));
        self::assertSame($reopened, $this->finding()['reopened_by_person_at']);
        self::assertCount(2, $this->comments($id));

        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'affected'");
        $this->sync();
        self::assertSame('open', $this->finding()['status']);
        self::assertNull($this->finding()['reopened_by_person_at']);
        self::assertSame([SubtaskModel::STATUS_TODO], $this->subtaskStatuses($id));
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'fixed'");
        $this->sync();
        self::assertTrue($this->container['taskStatusModel']->isClosed($id));
        self::assertCount(4, $this->comments($id));
    }

    public function testDismissedTaskGetsNoFixComment(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        self::assertTrue($this->container['taskStatusModel']->close($id));
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'fixed'");
        $this->sync(1, [1 => ['to' => 'fixed']]);
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertSame([], $this->comments($id));
    }

    public function testUnknownTransitionUsesOutcomeField(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'unknown'");
        $this->sync(1, [1 => ['to' => 'unknown', 'outcome' => 'inaccessible']]);
        self::assertSame(['symfony/yaml is no longer scanned (inaccessible); its status is unknown.'], $this->comments($id));
    }

    public function testFixClosesSubtaskAndThenTaskExactlyOnce(): void
    {
        $this->addRepo();
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'unknown' WHERE repo_id = 1");
        $this->sync();
        self::assertStringEndsWith('(1 repo)', $this->container['taskFinderModel']->getById($id)['title']);
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'fixed' WHERE repo_id = 1");
        $this->sync();
        self::assertSame([SubtaskModel::STATUS_DONE, SubtaskModel::STATUS_TODO], $this->subtaskStatuses($id));
        self::assertTrue($this->container['taskStatusModel']->isOpen($id));

        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'fixed'");
        $this->sync();
        $this->sync();
        self::assertTrue($this->container['taskStatusModel']->isClosed($id));
        self::assertSame('fixed', $this->finding()['status']);
        self::assertStringEndsWith('(1 repo)', $this->container['taskFinderModel']->getById($id)['title']);
        self::assertGreaterThan(0, (int) $this->finding()['closed_by_gumshoe_at']);
        self::assertSame(['Fixed in symfony/yaml.', 'Fixed in symfony/console.', 'Fixed in all repos.'], $this->comments($id));
    }

    public static function escalations(): array
    {
        return [
            ['UPDATE gumshoe_groups SET cvss_max = 8 WHERE id = 1', 'priority rose to high', false, false],
            ['UPDATE gumshoe_groups SET malware = 1 WHERE id = 1', 'now known malware', false, true],
            ['UPDATE gumshoe_groups SET kev = 1 WHERE id = 1', 'now on CISA KEV', false, true],
            ['', 'new repo affected: symfony/console', true, false],
        ];
    }

    /** @dataProvider escalations */
    public function testHumanCloseDismissesUntilEscalation(string $update, string $reason, bool $newRepo, bool $alreadyUrgent): void
    {
        if ($alreadyUrgent) {
            $flag = str_contains($update, 'malware') ? 'kev' : 'malware';
            $this->pdo->exec("UPDATE gumshoe_groups SET $flag = 1 WHERE id = 1");
        }

        $this->sync();
        $id = (int) $this->finding()['task_id'];
        self::assertTrue($this->container['taskStatusModel']->close($id));
        $this->sync();
        $this->sync();
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertSame([SubtaskModel::STATUS_DONE], $this->subtaskStatuses($id));

        if ($newRepo) {
            $this->addRepo();
        } else {
            $this->pdo->exec($update);
        }

        $this->sync();
        $this->sync();
        self::assertSame('open', $this->finding()['status']);
        self::assertSame(array_fill(0, $newRepo ? 2 : 1, SubtaskModel::STATUS_TODO), $this->subtaskStatuses($id));
        self::assertSame(["Reopened: $reason."], $this->comments($id));
    }

    public function testCloseBetweenReadAndWriteWinsOverEscalation(): void
    {
        $finder = new class($this->container) extends TaskFinderModel {
            public bool $interrupt = false;

            public function getById($taskId)
            {
                $task = parent::getById($taskId);
                if ($this->interrupt) {
                    $this->interrupt = false;
                    $this->taskStatusModel->close($taskId);
                }

                return $task;
            }
        };
        $this->container['taskFinderModel'] = $finder;
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $this->pdo->exec('UPDATE gumshoe_groups SET kev = 1 WHERE id = 1');
        $finder->interrupt = true;
        $this->sync();
        $this->sync();
        self::assertTrue($this->container['taskStatusModel']->isClosed($id));
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertSame([SubtaskModel::STATUS_DONE], $this->subtaskStatuses($id));
        self::assertSame([], $this->comments($id));
    }

    public function testMergeKeepsOpenAbsorbedTaskWhenSurvivorWasClosedByPerson(): void
    {
        $this->addMergeFinding();
        $this->sync();
        $this->sync(2);
        $old = (int) $this->finding()['task_id'];
        $absorbed = (int) $this->finding(2)['task_id'];
        self::assertTrue($this->container['taskStatusModel']->close($old));
        $this->sync();
        $closedAt = $this->container['taskFinderModel']->getById($old)['date_completed'];
        $this->mergeInto(1, 2);

        $this->sync(2);
        $this->sync();
        $this->sync(2);
        self::assertSame($absorbed, (int) $this->finding()['task_id']);
        self::assertSame('open', $this->finding()['status']);
        self::assertNull($this->finding()['closed_by_gumshoe_at']);
        $kept = $this->container['taskFinderModel']->getById($absorbed);
        self::assertSame('gumshoe:finding:1', $kept['reference']);
        self::assertSame('[Gumshoe] flatmap-stream — CVE-2018-16492 (2 repos)', $kept['title']);
        self::assertTrue($this->container['taskStatusModel']->isOpen($absorbed));
        self::assertSame([], $this->comments($absorbed));
        self::assertSame(["Merged into #$absorbed."], $this->comments($old));
        self::assertTrue($this->container['taskStatusModel']->isClosed($old));
        self::assertSame($closedAt, $this->container['taskFinderModel']->getById($old)['date_completed']);
        self::assertSame([SubtaskModel::STATUS_TODO, SubtaskModel::STATUS_TODO], $this->subtaskStatuses($absorbed));
    }

    public function testFreshSurvivorAdoptsActiveTaskAheadOfEarlierClosedTask(): void
    {
        $this->addMergeFinding();
        $this->pdo->exec("INSERT INTO gumshoe_groups (id, primary_id) VALUES (3, 'CVE-2021-44228')");
        $this->sync();
        $this->sync(2);
        $closed = (int) $this->finding()['task_id'];
        $active = (int) $this->finding(2)['task_id'];
        self::assertTrue($this->container['taskStatusModel']->close($closed));
        $this->sync();

        $merged = $this->mergeInto(3, 1, 2);
        $survivor = $merged[1]['survivor_finding_id'];
        $this->sync();
        $this->sync($survivor);
        $this->sync(2);

        self::assertSame($active, (int) $this->finding($survivor)['task_id']);
        self::assertSame('open', $this->finding($survivor)['status']);
        self::assertTrue($this->container['taskStatusModel']->isOpen($active));
        self::assertSame([], $this->comments($active));
        self::assertTrue($this->container['taskStatusModel']->isClosed($closed));
        self::assertSame(["Merged into #$active."], $this->comments($closed));
    }

    public function testDeletedSurvivorDoesNotAdoptClosedAbsorbedTask(): void
    {
        $this->addMergeFinding();
        $this->sync();
        $this->sync(2);
        $deleted = (int) $this->finding()['task_id'];
        $closed = (int) $this->finding(2)['task_id'];
        self::assertTrue($this->container['taskModel']->remove($deleted));
        self::assertTrue($this->container['taskStatusModel']->close($closed));
        $this->sync();
        // Merge before Gumshoe has seen the absorbed task close.
        $this->mergeInto(1, 2);

        $this->sync(2);
        $this->sync();
        self::assertNull($this->finding()['task_id']);
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertSame('gumshoe:finding:2', $this->container['taskFinderModel']->getById($closed)['reference']);
        self::assertTrue($this->container['taskStatusModel']->isClosed($closed));
    }

    public static function deletionTiming(): array
    {
        return ['recorded' => [true], 'before sync' => [false]];
    }

    /** @dataProvider deletionTiming */
    public function testDeletedSurvivorLeavesActiveAbsorbedTaskUntouched(bool $recordDeletion): void
    {
        $this->addMergeFinding();
        $this->sync();
        $this->sync(2);
        $deleted = (int) $this->finding()['task_id'];
        $absorbed = (int) $this->finding(2)['task_id'];
        self::assertTrue($this->container['taskModel']->remove($deleted));
        if ($recordDeletion) {
            $this->sync();
        }
        $before = $this->container['taskFinderModel']->getById($absorbed);
        $this->mergeInto(1, 2);

        $this->sync(2);
        $this->sync();
        self::assertNull($this->finding()['task_id']);
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertSame('merged', $this->finding(2)['status']);
        self::assertSame($before, $this->container['taskFinderModel']->getById($absorbed));
        self::assertTrue($this->container['taskStatusModel']->isOpen($absorbed));
        self::assertSame([], $this->comments($absorbed));
        self::assertSame(1, $this->container['taskFinderModel']->countByProjectId($this->project));
    }

    public function testMergeKeepsFixedTaskClosedWhenAbsorbedTaskWasJustDismissed(): void
    {
        $this->addMergeFinding();
        $this->pdo->exec('UPDATE gumshoe_groups SET cvss_max = 8 WHERE id = 2');
        $this->sync();
        $this->sync(2);
        $fixed = (int) $this->finding()['task_id'];
        $closed = (int) $this->finding(2)['task_id'];
        $this->pdo->exec("UPDATE gumshoe_finding_repos SET state = 'fixed' WHERE finding_id = 1");
        $this->sync();
        self::assertTrue($this->container['taskStatusModel']->close($closed));

        $this->mergeInto(1, 2);
        $this->pdo->exec('UPDATE gumshoe_groups SET cvss_max = 8 WHERE id = 1');
        $this->sync();
        $this->sync();
        self::assertSame($fixed, (int) $this->finding()['task_id']);
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertTrue($this->container['taskStatusModel']->isClosed($fixed));
        self::assertTrue($this->container['taskStatusModel']->isClosed($closed));
        self::assertSame(['Fixed in symfony/yaml.', 'Fixed in all repos.'], $this->comments($fixed));
        self::assertSame(["Merged into #$fixed."], $this->comments($closed));
    }

    public function testFreshSurvivorSkipsPreviouslyMergedClosedTaskAfterIntermediateDeletion(): void
    {
        $this->addMergeFinding();
        $this->pdo->exec("INSERT INTO gumshoe_groups (id, primary_id) VALUES (3, 'CVE-2021-44228')");
        $this->sync();
        $this->sync(2);
        $original = (int) $this->finding()['task_id'];
        $intermediate = (int) $this->finding(2)['task_id'];
        $this->mergeInto(2, 1);
        $this->sync();
        self::assertSame(["Merged into #$intermediate."], $this->comments($original));
        self::assertTrue($this->container['taskModel']->remove($intermediate));
        $this->sync(2);
        $survivor = $this->mergeInto(3, 2)[2]['survivor_finding_id'];

        $this->sync($survivor);
        self::assertNull($this->finding($survivor)['task_id']);
        self::assertSame('dismissed', $this->finding($survivor)['status']);
        self::assertSame('gumshoe:finding:1', $this->container['taskFinderModel']->getById($original)['reference']);
        self::assertSame(["Merged into #$intermediate."], $this->comments($original));
    }

    public function testCyclicReverseMergeChainTerminates(): void
    {
        $this->addMergeFinding();
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        self::assertTrue($this->container['taskStatusModel']->close($id));
        $this->pdo->exec(<<<'SQL'
            UPDATE gumshoe_groups SET merged_into = CASE id WHEN 1 THEN 2 ELSE 1 END;
            UPDATE gumshoe_findings SET status = 'merged' WHERE id = 2
            SQL);

        $this->sync();
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertTrue($this->container['taskStatusModel']->isClosed($id));
    }

    public function testInterruptedRecreationSkipsOldClosedSurvivorWithSameReference(): void
    {
        $this->addMergeFinding();
        $this->sync();
        $this->sync(2);
        $old = (int) $this->finding()['task_id'];
        self::assertTrue($this->container['taskStatusModel']->close($old));
        $this->mergeInto(1, 2);
        $this->sync();
        $adopted = (int) $this->finding()['task_id'];
        self::assertNotSame($old, $adopted);
        self::assertTrue($this->container['taskModel']->remove($adopted));
        $this->sync();

        $interrupt = true;
        $this->container['hook']->on('model:task:creation:aftersave', static function () use (&$interrupt) {
            if ($interrupt) {
                throw new RuntimeException('Recreation interrupted');
            }
        });
        $this->pdo->exec('UPDATE gumshoe_groups SET cvss_max = 8 WHERE id = 1');
        $this->assertInterrupted('Recreation interrupted');
        $interrupt = false;
        $this->sync();

        $recreated = (int) $this->finding()['task_id'];
        self::assertNotSame($old, $recreated);
        self::assertTrue($this->container['taskStatusModel']->isOpen($recreated));
        self::assertTrue($this->container['taskStatusModel']->isClosed($old));
        self::assertSame(["Merged into #$adopted."], $this->comments($old));
        self::assertSame(2, $this->container['taskFinderModel']->countByProjectId($this->project));
    }

    public function testPersonClosedTaskKeepsItsTitle(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        self::assertTrue($this->container['taskStatusModel']->close($id));
        $title = $this->container['taskFinderModel']->getById($id)['title'];
        $this->pdo->exec("UPDATE gumshoe_groups SET primary_id = 'CVE-2021-44228' WHERE id = 1");

        $this->sync();
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertSame($title, $this->container['taskFinderModel']->getById($id)['title']);
    }

    public function testEscalationDoesNotAnnounceReopenWhenPersonAlreadyOpenedTask(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        self::assertTrue($this->container['taskStatusModel']->close($id));
        $this->sync();
        self::assertTrue($this->container['taskStatusModel']->open($id));
        $this->pdo->exec('UPDATE gumshoe_groups SET cvss_max = 8 WHERE id = 1');

        $this->sync();
        self::assertSame('open', $this->finding()['status']);
        self::assertSame([], $this->comments($id));
        self::assertSame([SubtaskModel::STATUS_TODO], $this->subtaskStatuses($id));
    }

    public static function adoptionCases(): array
    {
        return [[false, true], [true, false]];
    }

    /** @dataProvider adoptionCases */
    public function testFreshSurvivorAdoptsTaskAndHistory(bool $dismissed, bool $syncSurvivorFirst): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $column = $this->container['columnModel']->create($this->project, 'Investigating');
        $user = $this->container['userModel']->create(['username' => 'analyst']);
        self::assertTrue($this->container['taskModificationModel']->update(['id' => $id, 'owner_id' => $user, 'column_id' => $column]));
        self::assertGreaterThan(0, $this->container['commentModel']->create(['task_id' => $id, 'user_id' => $user, 'comment' => 'Investigating']));
        if ($dismissed) {
            self::assertTrue($this->container['taskStatusModel']->close($id));
            $this->sync();
        }
        $this->pdo->exec('UPDATE gumshoe_groups SET merged_into = 2 WHERE id = 1');
        $merge = (new FindingModel($this->pdo))->mergeAbsorbedFindings();
        $survivor = $merge[1]['survivor_finding_id'];

        $this->sync($syncSurvivorFirst ? $survivor : 1);
        $this->sync($syncSurvivorFirst ? 1 : $survivor);
        self::assertSame($id, (int) $this->finding($survivor)['task_id']);
        self::assertSame(1, $this->container['taskFinderModel']->countByProjectId($this->project));
        $task = $this->container['taskFinderModel']->getById($id);
        self::assertSame("gumshoe:finding:$survivor", $task['reference']);
        self::assertSame('[Gumshoe] flatmap-stream — GHSA-mh6f-8j2x-4483 (1 repo)', $task['title']);
        self::assertSame($column, (int) $task['column_id']);
        self::assertSame($user, (int) $task['owner_id']);
        self::assertSame(['Investigating'], $this->comments($id));
        self::assertSame(!$dismissed, (bool) $task['is_active']);
        self::assertSame($dismissed ? 'dismissed' : 'open', $this->finding($survivor)['status']);
    }

    public function testRepeatedMergeAdoptsThePreviousSurvivorTask(): void
    {
        $this->pdo->exec(<<<'SQL'
            INSERT INTO gumshoe_groups (id, primary_id) VALUES (3, 'CVE-2021-44228');
            INSERT INTO gumshoe_findings (group_id, ecosystem, package) VALUES (2, 'npm', 'flatmap-stream');
            INSERT INTO gumshoe_finding_repos (finding_id, repo_id, state, ever_affected) VALUES (2, 2, 'affected', 1)
            SQL);
        $this->sync();
        $this->sync(2);
        $original = (int) $this->finding()['task_id'];
        $firstSurvivor = (int) $this->finding(2)['task_id'];
        $findings = new FindingModel($this->pdo);
        $this->pdo->exec('UPDATE gumshoe_groups SET merged_into = 2 WHERE id = 1');
        $findings->mergeAbsorbedFindings();
        $this->sync();
        $this->pdo->exec('UPDATE gumshoe_groups SET merged_into = 3 WHERE id = 2');
        $survivor = $findings->mergeAbsorbedFindings()[2]['survivor_finding_id'];
        $this->sync(2);

        self::assertSame($firstSurvivor, (int) $this->finding($survivor)['task_id']);
        self::assertTrue($this->container['taskStatusModel']->isClosed($original));
        self::assertTrue($this->container['taskStatusModel']->isOpen($firstSurvivor));
        self::assertSame(["Merged into #$firstSurvivor."], $this->comments($original));
        self::assertSame([], $this->comments($firstSurvivor));
    }

    public function testMergeOfDismissedFindingsKeepsSurvivorDismissed(): void
    {
        $this->pdo->exec(<<<'SQL'
            UPDATE gumshoe_groups SET kev = 1 WHERE id = 2;
            INSERT INTO gumshoe_findings (group_id, ecosystem, package) VALUES (2, 'npm', 'flatmap-stream');
            INSERT INTO gumshoe_finding_repos (finding_id, repo_id, state, ever_affected) VALUES (2, 2, 'affected', 1)
            SQL);
        $this->sync();
        $this->sync(2);
        $survivor = (int) $this->finding()['task_id'];
        $absorbed = (int) $this->finding(2)['task_id'];
        $this->container['taskStatusModel']->close($survivor);
        $this->container['taskStatusModel']->close($absorbed);
        $this->sync();
        $this->sync(2);
        $this->pdo->exec('UPDATE gumshoe_groups SET merged_into = 1 WHERE id = 2; UPDATE gumshoe_groups SET kev = 1 WHERE id = 1');
        (new FindingModel($this->pdo))->mergeAbsorbedFindings();

        // The scanner can reach the survivor before it reaches the absorbed ID.
        $this->sync();
        $this->sync(2);
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertTrue($this->container['taskStatusModel']->isClosed($survivor));
        self::assertSame([SubtaskModel::STATUS_DONE, SubtaskModel::STATUS_DONE], $this->subtaskStatuses($survivor));
        self::assertSame(["Merged into #$survivor."], $this->comments($absorbed));
    }

    public function testMovedTaskStaysOnItsActualBoardAndNewFindingsUseNewTarget(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $moved = $this->container['projectModel']->create(['name' => 'Moved']);
        $new = $this->container['projectModel']->create(['name' => 'New findings']);
        self::assertTrue($this->container['taskProjectMoveModel']->moveToProject($id, $moved));
        $this->project = $new;
        $this->pdo->exec(<<<'SQL'
            INSERT INTO gumshoe_findings (group_id, ecosystem, package) VALUES (2, 'npm', 'flatmap-stream');
            INSERT INTO gumshoe_finding_repos (finding_id, repo_id, state, ever_affected) VALUES (2, 2, 'affected', 1)
            SQL);
        $this->sync();
        $this->sync(2);
        self::assertSame($moved, (int) $this->finding()['project_id']);
        self::assertSame($id, (int) $this->finding()['task_id']);
        self::assertSame($new, (int) $this->finding(2)['project_id']);
    }

    public function testDeletedTaskRecreatedOnlyForEscalation(): void
    {
        $this->pdo->exec('UPDATE gumshoe_groups SET kev = 1 WHERE id = 1');
        $this->sync();
        self::assertSame('urgent', $this->finding()['observed_priority']);
        self::assertSame(0, (int) $this->finding()['observed_malware']);
        self::assertSame(1, (int) $this->finding()['observed_kev']);
        self::assertSame('open', $this->finding()['observed_status']);
        self::assertSame(0, (int) $this->pdo->query('SELECT COUNT(*) FROM project_has_metadata')->fetchColumn());
        $id = (int) $this->finding()['task_id'];
        self::assertTrue($this->container['taskModel']->remove($id));
        $this->sync();
        $this->sync();
        self::assertNull($this->finding()['task_id']);
        self::assertSame('dismissed', $this->finding()['status']);

        $this->pdo->exec('UPDATE gumshoe_groups SET malware = 1 WHERE id = 1');
        $this->sync();
        self::assertSame('open', $this->finding()['status']);
        self::assertTrue($this->container['taskStatusModel']->isOpen((int) $this->finding()['task_id']));
        self::assertSame([], $this->comments((int) $this->finding()['task_id']));
    }

    public function testPublicOrMissingTargetRecordsUnavailableWithoutWritingTasks(): void
    {
        $this->container['projectModel']->update(['id' => $this->project, 'is_public' => 1]);
        self::assertSame('project_unavailable', $this->sync());
        self::assertSame(0, $this->container['taskFinderModel']->countByProjectId($this->project));
        $this->project += 100;
        self::assertSame('project_unavailable', $this->sync());
        self::assertNull($this->finding()['project_id']);
        $counts = json_decode($this->pdo->query('SELECT counts FROM gumshoe_runs WHERE id = 1')->fetchColumn(), true);
        self::assertArrayHasKey('project_unavailable', $counts);
    }

    public static function recreationBoards(): array
    {
        return ['private' => ['private'], 'public' => ['public'], 'missing' => ['missing']];
    }

    /** @dataProvider recreationBoards */
    public function testEscalationAfterDeletionUsesOriginalBoard(string $visibility): void
    {
        $this->sync();
        $original = $this->project;
        self::assertTrue($this->container['taskModel']->remove((int) $this->finding()['task_id']));
        $this->sync();
        $this->project = $this->container['projectModel']->create(['name' => 'New findings']);
        if ($visibility === 'public') {
            $this->container['projectModel']->update(['id' => $original, 'is_public' => 1]);
        } elseif ($visibility === 'missing') {
            self::assertTrue($this->container['projectModel']->remove($original));
        }

        $this->pdo->exec('UPDATE gumshoe_groups SET cvss_max = 8 WHERE id = 1');
        $result = $this->sync();

        self::assertSame(0, $this->container['taskFinderModel']->countByProjectId($this->project));
        self::assertSame($original, (int) $this->finding()['project_id']);
        if ($visibility === 'private') {
            self::assertNull($result);
            $task = $this->container['taskFinderModel']->getByReference($original, 'gumshoe:finding:1');
            self::assertNotEmpty($task);
            self::assertSame((int) $task['id'], (int) $this->finding()['task_id']);
            self::assertSame('open', $this->finding()['status']);
        } else {
            self::assertSame('project_unavailable', $result);
            self::assertNull($this->finding()['task_id']);
            self::assertSame('dismissed', $this->finding()['status']);
            self::assertSame('normal', $this->finding()['observed_priority']);
            self::assertSame(0, $this->container['taskFinderModel']->countByProjectId($original));
        }
    }

    public function testInterruptedCreateFollowsTaskMovedToPrivateBoard(): void
    {
        $id = $this->interruptTaskCreation();
        $other = $this->container['projectModel']->create(['name' => 'Other']);
        self::assertTrue($this->container['taskProjectMoveModel']->moveToProject($id, $other));

        $this->sync();
        $this->sync();

        self::assertSame($id, (int) $this->finding()['task_id']);
        self::assertSame($other, (int) $this->finding()['project_id']);
        self::assertSame(0, $this->container['taskFinderModel']->countByProjectId($this->project));
        self::assertSame(1, $this->container['taskFinderModel']->countByProjectId($other));
        self::assertSame(['symfony/yaml'], array_column($this->container['subtaskModel']->getAll($id), 'title'));
    }

    public function testInterruptedCreateLeavesTaskMovedToPublicBoardUntouched(): void
    {
        $id = $this->interruptTaskCreation();
        $other = $this->container['projectModel']->create(['name' => 'Other']);
        self::assertTrue($this->container['taskProjectMoveModel']->moveToProject($id, $other));
        $this->container['projectModel']->update(['id' => $other, 'is_public' => 1]);
        $before = $this->container['taskFinderModel']->getById($id);
        $claim = $this->finding();

        self::assertSame('project_unavailable', $this->sync());
        self::assertSame($claim, $this->finding());
        self::assertSame($before, $this->container['taskFinderModel']->getById($id));
        self::assertSame([], $this->container['subtaskModel']->getAll($id));
        self::assertSame(0, $this->container['taskFinderModel']->countByProjectId($this->project));
        $counts = json_decode($this->pdo->query('SELECT counts FROM gumshoe_runs WHERE id = 1')->fetchColumn(), true);
        self::assertSame(BoardSync::PUBLIC_BOARD_MESSAGE, $counts['project_unavailable_message'] ?? null);
    }

    public function testInterruptedCreateDismissesDeletedTaskUntilEscalation(): void
    {
        $id = $this->interruptTaskCreation();
        self::assertTrue($this->container['taskModel']->remove($id));

        $this->sync();
        $this->sync();

        self::assertNull($this->finding()['task_id']);
        self::assertSame('dismissed', $this->finding()['status']);
        self::assertSame($this->project, (int) $this->finding()['project_id']);
        self::assertSame(0, $this->container['taskFinderModel']->countByProjectId($this->project));

        $this->pdo->exec('UPDATE gumshoe_groups SET cvss_max = 8 WHERE id = 1');
        $this->sync();
        self::assertSame('open', $this->finding()['status']);
        self::assertSame(1, $this->container['taskFinderModel']->countByProjectId($this->project));
    }

    public function testInterruptedCreateWithAmbiguousReferenceLogsAndLeavesBothTasksUntouched(): void
    {
        $id = $this->interruptTaskCreation();
        $other = $this->container['projectModel']->create(['name' => 'Other']);
        $duplicate = $this->container['taskCreationModel']->create([
            'project_id' => $other, 'title' => 'Other task', 'reference' => 'gumshoe:finding:1',
        ]);
        $finder = $this->container['taskFinderModel'];
        $before = [$finder->getById($id), $finder->getById($duplicate)];
        $claim = $this->finding();

        $this->sync();

        self::assertSame($claim, $this->finding());
        self::assertSame($before, [$finder->getById($id), $finder->getById($duplicate)]);
        self::assertSame([], $this->container['subtaskModel']->getAll($id));
        self::assertSame([], $this->container['subtaskModel']->getAll($duplicate));
        $counts = json_decode($this->pdo->query('SELECT counts FROM gumshoe_runs WHERE id = 1')->fetchColumn(), true);
        self::assertSame(1, $counts['task_recovery_ambiguous'] ?? null);
    }

    public function testMovedTaskOnPublicBoardGetsNoWrites(): void
    {
        $this->sync();
        $id = (int) $this->finding()['task_id'];
        $public = $this->container['projectModel']->create(['name' => 'Public']);
        self::assertTrue($this->container['taskProjectMoveModel']->moveToProject($id, $public));
        $this->container['projectModel']->update(['id' => $public, 'is_public' => 1]);
        $before = $this->container['taskFinderModel']->getById($id);
        $this->addRepo();

        self::assertSame('project_unavailable', $this->sync());
        self::assertSame($before, $this->container['taskFinderModel']->getById($id));
        self::assertSame(['symfony/yaml'], array_column($this->container['subtaskModel']->getAll($id), 'title'));
        self::assertSame([], $this->comments($id));
        $counts = json_decode($this->pdo->query('SELECT counts FROM gumshoe_runs WHERE id = 1')->fetchColumn(), true);
        self::assertSame(1, $counts['project_unavailable']);
        self::assertSame('The findings board is public; Gumshoe will not write private repo names to it.',
            $counts['project_unavailable_message'] ?? null);
    }

    private function addMergeFinding(): void
    {
        $this->pdo->exec(<<<'SQL'
            INSERT INTO gumshoe_findings (group_id, ecosystem, package) VALUES (2, 'npm', 'flatmap-stream');
            INSERT INTO gumshoe_finding_repos (finding_id, repo_id, state, ever_affected) VALUES (2, 2, 'affected', 1)
            SQL);
    }

    private function mergeInto(int $survivor, int ...$absorbed): array
    {
        $groups = implode(', ', $absorbed);
        $this->pdo->exec("UPDATE gumshoe_groups SET merged_into = $survivor WHERE id IN ($groups)");

        return (new FindingModel($this->pdo))->mergeAbsorbedFindings();
    }

    private function addRepo(): void
    {
        $this->pdo->exec("INSERT INTO gumshoe_finding_repos (finding_id, repo_id, state, ever_affected) VALUES (1, 2, 'affected', 1)");
    }

    private function sync(int $finding = 1, array $transitions = []): ?string
    {
        return (new BoardSync($this->container))->sync($finding, $this->project, 1, $transitions);
    }

    private function finding(int $id = 1): array
    {
        return $this->pdo->query("SELECT * FROM gumshoe_findings WHERE id = $id")->fetch(PDO::FETCH_ASSOC);
    }

    private function comments(int $taskId): array
    {
        return array_column($this->container['commentModel']->getAll($taskId), 'comment');
    }

    private function subtaskStatuses(int $taskId): array
    {
        return array_map('intval', array_column($this->container['subtaskModel']->getAll($taskId), 'status'));
    }

    private function interruptTaskCreation(): int
    {
        $interrupt = true;
        $this->container['hook']->on('model:task:creation:aftersave', static function () use (&$interrupt) {
            if ($interrupt) {
                $interrupt = false;
                throw new RuntimeException('Task interrupted');
            }
        });
        $this->assertInterrupted('Task interrupted');
        $task = $this->container['taskFinderModel']->getByReference($this->project, 'gumshoe:finding:1');
        self::assertNotEmpty($task);
        self::assertSame(0, (int) $this->finding()['task_id']);

        return (int) $task['id'];
    }

    private function assertInterrupted(string $message): void
    {
        try {
            $this->sync();
            self::fail('Expected an interruption');
        } catch (RuntimeException $error) {
            self::assertSame($message, $error->getMessage());
        }
    }
}
