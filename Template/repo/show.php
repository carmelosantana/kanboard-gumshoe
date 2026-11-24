<?php
$e = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section id="gumshoe-repo">
    <div class="page-header"><h2><?= $e($repo['login'].'/'.$repo['name']) ?></h2></div>
    <dl>
        <dt>Scan outcome</dt>
        <dd><span data-slot="pill"><?= $e($repo['outcome'] ?? 'Not scanned') ?></span></dd>
        <dt>Last complete scan</dt>
        <dd><?= $repo['last_complete_at'] === null ? 'Never' : $e($this->dt->datetime($repo['last_complete_at'])) ?></dd>
    </dl>

    <h3>Dependencies by ecosystem</h3>
    <?php if ($dependencyCounts === []): ?>
        <div data-slot="empty"><p>No dependencies recorded.</p></div>
    <?php else: ?>
        <ul>
            <?php foreach ($dependencyCounts as $ecosystem => $count): ?>
                <li><?= $e($ecosystem) ?> <?= $count ?></li>
            <?php endforeach ?>
        </ul>
    <?php endif ?>

    <h3>Coverage gaps</h3>
    <ul>
        <?php foreach ($gaps as $verdict => $count): ?>
            <li><?= $e($verdict) ?> <?= $count ?></li>
        <?php endforeach ?>
    </ul>

    <?php if ($lockfiles === []): ?>
        <div data-slot="empty"><p>No lockfiles recorded.</p></div>
    <?php else: ?>
        <table class="table-striped">
            <caption>Lockfiles</caption>
            <thead><tr><th scope="col">Path</th><th scope="col">Status</th></tr></thead>
            <tbody>
                <?php foreach ($lockfiles as $file): ?>
                    <tr>
                        <td><?= $e($file['path']) ?></td>
                        <td><span data-slot="pill"><?= $e($file['status']) ?></span></td>
                    </tr>
                <?php endforeach ?>
            </tbody>
        </table>
    <?php endif ?>

    <?php if ($changes === []): ?>
        <div data-slot="empty"><p>No dependency changes recorded.</p></div>
    <?php else: ?>
        <table class="table-striped">
            <caption>Recent dependency changes</caption>
            <thead>
                <tr>
                    <th scope="col">Date</th>
                    <th scope="col">Change</th>
                    <th scope="col">Ecosystem</th>
                    <th scope="col">Package</th>
                    <th scope="col">From version</th>
                    <th scope="col">To version</th>
                    <th scope="col">Path</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($changes as $change): ?>
                    <tr>
                        <td><?= $e($this->dt->datetime($change['created_at'])) ?></td>
                        <?php foreach (['kind', 'ecosystem', 'name', 'from_version', 'to_version', 'path'] as $key): ?>
                            <td><?= $e($change[$key] ?? '—') ?></td>
                        <?php endforeach ?>
                    </tr>
                <?php endforeach ?>
            </tbody>
        </table>
    <?php endif ?>

    <?php if ($findings === []): ?>
        <div data-slot="empty"><p>No open findings for this repository.</p></div>
    <?php else: ?>
        <table class="table-striped">
            <caption>Open findings</caption>
            <thead>
                <tr>
                    <th scope="col">Advisory</th>
                    <th scope="col">Ecosystem</th>
                    <th scope="col">Package</th>
                    <th scope="col">Priority</th>
                    <th scope="col">Repo state</th>
                    <th scope="col">Task</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($findings as $finding): ?>
                    <tr>
                        <td><?= $e($finding['primary_id']) ?></td>
                        <td><?= $e($finding['ecosystem']) ?></td>
                        <td><?= $e($finding['package']) ?></td>
                        <td><span data-slot="pill"><?= $e($finding['priority']) ?></span></td>
                        <td><?= $e($finding['state']) ?></td>
                        <td>
                            <?php if ($finding['task_id'] === null): ?>
                                —
                            <?php else: ?>
                                <?= $this->url->link('#'.(int) $finding['task_id'], 'TaskViewController', 'show', [
                                    'task_id' => (int) $finding['task_id'], 'project_id' => (int) $finding['project_id'],
                                ]) ?>
                            <?php endif ?>
                        </td>
                    </tr>
                <?php endforeach ?>
            </tbody>
        </table>
    <?php endif ?>
</section>
