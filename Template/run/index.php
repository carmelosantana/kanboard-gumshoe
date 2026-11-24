<?php
$e = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
?>
<section>
    <div class="page-header"><h2>Run log</h2></div>
    <?php if ($runs === []): ?>
        <div data-slot="empty"><p>No runs recorded.</p></div>
    <?php else: ?>
        <table class="table-striped">
            <thead>
                <tr>
                    <th scope="col">Run</th>
                    <th scope="col">Started</th>
                    <th scope="col">Job</th>
                    <th scope="col">Trigger</th>
                    <th scope="col">Phase</th>
                    <th scope="col">Status</th>
                    <th scope="col">Counts</th>
                    <th scope="col">Retry at</th>
                    <th scope="col">Exception class</th>
                </tr>
            </thead>
            <tbody>
                <?php foreach ($runs as $run): ?>
                    <tr>
                        <td><?= (int) $run['id'] ?></td>
                        <td><?= $e($this->dt->datetime($run['started_at'])) ?></td>
                        <td><?= $e($run['job']) ?></td>
                        <td><?= $e($run['trigger']) ?></td>
                        <td><?= $e($run['phase']) ?></td>
                        <td><span data-slot="pill"><?= $e($run['status']) ?></span></td>
                        <td><?= $run['summary'] === [] ? '—' : $e(implode(' · ', $run['summary'])) ?></td>
                        <td><?= $run['retry_at'] === null ? '—' : $e($this->dt->datetime($run['retry_at'])) ?></td>
                        <td><?= $e($run['exception_class'] ?? '—') ?></td>
                    </tr>
                <?php endforeach ?>
            </tbody>
        </table>
    <?php endif ?>
</section>
