<?php
$e = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$back = $this->url->link(isset($error) ? 'Back to Sources' : 'Cancel', 'SourcesController', 'index', ['plugin' => 'Gumshoe']);
?>
<section class="gumshoe-sources">
    <div class="page-header"><h2>Review Sources</h2></div>
    <?php if (isset($error)): ?>
        <p data-slot="callout" data-tone="error" role="alert"><?= $e($error) ?></p>
        <p><?= $back ?></p>
    <?php else: ?>
        <?php if ($stale): ?>
            <p data-slot="callout" data-tone="warning" role="alert">Sources changed since this form was opened. Review your changes against the current settings before saving.</p>
        <?php endif ?>
        <?php if ($unknown !== []): ?>
            <h3>Unknown repositories</h3>
            <ul>
                <?php foreach ($unknown as $name): ?>
                    <li><?= $e($name) ?></li>
                <?php endforeach ?>
            </ul>
        <?php endif ?>
        <?php if ($changes['settings'] !== [] || $ownerChanges !== [] || $references !== [] || $repoChanges !== []): ?>
            <h3>Settings changes</h3>
            <ul>
                <?php
                $labels = ['scanning' => 'Scanning', 'hourly' => 'Hourly recheck', 'forks' => 'Include forks',
                    'archived' => 'Include archived', 'window_days' => 'Watch window (days)',
                    'project_id' => 'Findings board', 'deny_prefixes' => 'Deny prefixes'];
                ?>
                <?php foreach ($changes['settings'] as $key => $value): ?>
                    <?php
                    $value = match ($key) {
                        'project_id' => $boardName,
                        'window_days' => $value,
                        'deny_prefixes' => $value === '' ? 'None' : $value,
                        default => $value ? 'On' : 'Off',
                    };
                    ?>
                    <li><?= $labels[$key] ?> · <?= $e($value) ?></li>
                <?php endforeach ?>
                <?php foreach ($ownerChanges as $login => $label): ?>
                    <li><?= $e($login) ?> · <?= $label ?></li>
                <?php endforeach ?>
                <?php foreach ($references as $login => $token): ?>
                    <li><?= $e($login) ?> · Token <?= $e($token['status']) ?><?= $token['refStatus'] === null ? '' : ' · Vault '.$e($token['refStatus']) ?></li>
                <?php endforeach ?>
                <?php foreach ($repoChanges as $name => $mode): ?>
                    <li><?= $e($name) ?> · <?= ucfirst($mode) ?></li>
                <?php endforeach ?>
            </ul>
        <?php endif ?>
        <div class="gumshoe-overview">
            <?php foreach (['Added repos' => $added, 'Dropped repos' => $dropped] as $label => $items): ?>
                <div class="panel">
                    <h3><?= $label ?> (<?= count($items) ?>)</h3>
                    <?php if ($items !== []): ?>
                        <ul>
                            <?php foreach ($items as $name): ?>
                                <li><?= $e($name) ?></li>
                            <?php endforeach ?>
                        </ul>
                    <?php endif ?>
                </div>
            <?php endforeach ?>
        </div>
        <?php if ($dropped !== []): ?>
            <p>Dropped repos keep their history and open findings.</p>
        <?php endif ?>
        <?php if ($changes['settings'] === [] && $changes['owners'] === [] && $changes['repos'] === []): ?>
            <p>No pending changes. <?= $back ?></p>
        <?php else: ?>
            <form method="post" action="<?= $this->url->href('SourcesController', 'save', ['plugin' => 'Gumshoe']) ?>">
                <?= $this->form->csrf() ?>
                <input type="hidden" name="revision" value="<?= (int) $revision ?>">
                <?php foreach ($changes['settings'] as $key => $value): ?>
                    <input type="hidden" name="settings[<?= $e($key) ?>]" value="<?= $e($value ?? '0') ?>">
                <?php endforeach ?>
                <?php foreach ($changes['owners'] as $id => $owner): ?>
                    <?php foreach ($owner as $key => $value): ?>
                        <input type="hidden" name="owners[<?= (int) $id ?>][<?= $e($key) ?>]" value="<?= $e($value) ?>">
                    <?php endforeach ?>
                <?php endforeach ?>
                <?php foreach ($changes['repos'] as $id => $mode): ?>
                    <input type="hidden" name="repos[<?= (int) $id ?>]" value="<?= $e($mode) ?>">
                <?php endforeach ?>
                <div class="form-actions">
                    <button type="submit" class="btn btn-blue">Save</button>
                    <?= $back ?>
                </div>
            </form>
        <?php endif ?>
    <?php endif ?>
</section>
