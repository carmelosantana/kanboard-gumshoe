<?php
$e = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$url = fn (string $action): string => $this->url->href('SourcesController', $action, ['plugin' => 'Gumshoe']);
?>
<section class="gumshoe-sources">
    <div class="page-header"><h2>Sources</h2></div>
    <div class="gumshoe-overview">
        <div class="panel">
            <strong><?= $counts['watched'] ?> of <?= $counts['total'] ?> watched</strong><br>
            <?= $counts['pin'] ?> pinned · <?= $counts['exclude'] ?> excluded
        </div>
        <div class="panel">
            <strong>Tokens</strong><br>
            <?php foreach ($tokens as $status => $count): ?>
                <span data-slot="pill"><?= $count ?> <?= $e($status) ?></span>
            <?php endforeach ?>
            <?php if ($tokens['ok'] < array_sum($tokens)): ?>
                <br><a href="#gumshoe-owners" data-needs-token>Show owners needing a token</a>
            <?php endif ?>
        </div>
        <div class="panel">
            <strong>Last run</strong> <?= $last === null ? 'Never' : $e($this->dt->datetime($last['started_at']).' · '.$last['status']) ?><br>
            <strong>Next due</strong> <?= $e($next) ?>
        </div>
        <div class="panel">
            <strong>Open findings</strong><br>
            <?php foreach ($findings as $priority => $count): ?>
                <span data-slot="pill"><?= $count ?> <?= $e($priority) ?></span>
            <?php endforeach ?>
            <?php if ($project !== null && $warning === null): ?>
                <br><?= $this->url->link('Open findings board', 'BoardViewController', 'show', ['project_id' => $project['id']]) ?>
            <?php endif ?>
        </div>
    </div>
    <?php if ($vault === null): ?>
        <p data-slot="callout" data-tone="warning">Gumshoe needs Vault 1.1.0 with Server sharing on.</p>
    <?php endif ?>
    <form method="post" action="<?= $url('review') ?>" class="js-gumshoe-sources">
        <?= $this->form->csrf() ?>
        <input type="hidden" name="revision" value="<?= (int) $settings['revision'] ?>">
        <fieldset class="panel">
            <legend>Quick settings</legend>
            <div class="gumshoe-controls">
                <?php foreach (['scanning' => 'Scanning on', 'hourly' => 'Hourly recheck', 'forks' => 'Include forks', 'archived' => 'Include archived'] as $key => $label): ?>
                    <label>
                        <input type="hidden" name="settings[<?= $key ?>]" value="0">
                        <input type="checkbox" name="settings[<?= $key ?>]" value="1" <?= $settings[$key] ? 'checked' : '' ?>>
                        <?= $label ?>
                    </label>
                <?php endforeach ?>
            </div>
            <label for="gumshoe-project">Findings board</label>
            <select id="gumshoe-project" data-slot="control" name="settings[project_id]" aria-describedby="gumshoe-public-board">
                <option value="0">No board selected</option>
                <?php foreach ($projects as $option): ?>
                    <option value="<?= (int) $option['id'] ?>" data-public="<?= (int) $option['is_public'] ?>"
                        <?= $option['id'] == $settings['project_id'] ? 'selected' : '' ?>>
                        <?= $e($option['name']) ?><?= $option['is_public'] ? ' (public)' : '' ?>
                    </option>
                <?php endforeach ?>
            </select>
            <p id="gumshoe-public-board" data-slot="callout" data-tone="warning" role="status" <?= $warning === null ? 'hidden' : '' ?>>
                The findings board is public; Gumshoe will not write private repo names to it.
            </p>
            <label for="gumshoe-window">Watch window (days)</label>
            <input id="gumshoe-window" data-slot="control" type="number" min="1" max="2147483647" required
                   name="settings[window_days]" value="<?= (int) $settings['window_days'] ?>">
            <label for="gumshoe-deny">Deny prefixes (comma or newline separated)</label>
            <textarea id="gumshoe-deny" name="settings[deny_prefixes]" rows="2"><?= $e($settings['deny_prefixes']) ?></textarea>
        </fieldset>

        <div class="gumshoe-controls" data-slot="toolbar">
            <input type="search" data-slot="toolbar-search" data-repo-search aria-label="Filter repositories" placeholder="Filter repos…">
            <select data-slot="control" data-repo-filter aria-label="Watch filter">
                <?php foreach (['all' => 'All', 'watching' => 'Watching', 'not-watching' => 'Not watching', 'pin' => 'Pinned', 'exclude' => 'Excluded'] as $key => $label): ?>
                    <option value="<?= $key ?>"><?= $label ?></option>
                <?php endforeach ?>
            </select>
            <span data-no-results role="status" hidden>No repositories match.</span>
        </div>

        <div id="gumshoe-owners">
            <?php foreach ($owners as $owner): ?>
                <?= $this->render('Gumshoe:sources/owner', ['owner' => $owner, 'vaultAvailable' => $vault !== null,
                    'ownerUrl' => $url('owner'), 'first' => $owner['id'] == array_key_first($owners)]) ?>
            <?php endforeach ?>
        </div>

        <details class="panel">
            <summary>Import pins</summary>
            <label for="gumshoe-pins">Repository names or GitHub URLs, one per line</label>
            <textarea id="gumshoe-pins" name="pins" rows="4"></textarea>
            <button class="btn" type="submit" formaction="<?= $url('importPins') ?>">Review imported pins</button>
        </details>
        <div class="form-actions">
            <button type="submit" class="btn btn-blue">Review &amp; save…</button>
        </div>
    </form>
</section>
