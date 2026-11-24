<?php
$e = static fn (mixed $value): string => htmlspecialchars((string) $value, ENT_QUOTES | ENT_SUBSTITUTE, 'UTF-8');
$id = (int) $owner['id'];
$ref = $owner['token_ref'] ?? '';
$repoPageAvailable = class_exists(\Kanboard\Plugin\Gumshoe\Controller\RepoController::class);
?>
<details class="panel gumshoe-owner" data-owner-status="<?= $e($owner['status']) ?>" <?= $first ? 'open' : '' ?>>
    <summary>
        <strong><?= $e($owner['login']) ?></strong>
        <span data-slot="pill">Token <?= $e($owner['status']) ?></span>
        <span><?= $owner['watched'] ?> of <?= count($owner['repos']) ?> watched</span>
    </summary>
    <label>
        <input type="hidden" name="owners[<?= $id ?>][enabled]" value="0">
        <input type="checkbox" name="owners[<?= $id ?>][enabled]" value="1" <?= $owner['enabled'] ? 'checked' : '' ?>>
        Watch <?= $e($owner['login']) ?>
    </label>
    <?php if ($vaultAvailable): ?>
        <label for="gumshoe-ref-<?= $id ?>">Vault token reference</label>
        <input type="text" id="gumshoe-ref-<?= $id ?>" data-slot="control" name="owners[<?= $id ?>][token_ref]"
               placeholder="vault://17/token" autocomplete="off"
               value="<?= preg_match('~\Avault://[1-9][0-9]{0,17}/token\z~', $ref) === 1 ? $e($ref) : '' ?>">
        <?php if ($owner['refStatus'] !== null): ?>
            <span data-slot="pill">Vault <?= $e($owner['refStatus']) ?></span>
        <?php endif ?>
        <button class="btn" type="submit" name="owner_id" value="<?= $id ?>" formaction="<?= $ownerUrl ?>">Review owner settings</button>
    <?php endif ?>
    <?php if ($owner['repos'] === []): ?>
        <p>No repositories discovered.</p>
    <?php else: ?>
        <table class="table-striped">
            <thead><tr><th scope="col">Repository</th><th scope="col">Coverage</th><th scope="col">Watch mode</th></tr></thead>
            <tbody>
                <?php foreach ($owner['repos'] as $repo): ?>
                    <?php
                    $fullName = $owner['login'].'/'.$repo['name'];
                    $data = json_encode(['name' => $fullName, 'watched' => $repo['watched'], 'mode' => $repo['mode']],
                        JSON_HEX_TAG | JSON_HEX_AMP | JSON_HEX_APOS | JSON_HEX_QUOT | JSON_UNESCAPED_SLASHES
                        | JSON_INVALID_UTF8_SUBSTITUTE | JSON_THROW_ON_ERROR);
                    ?>
                    <tr data-repo="<?= $e($data) ?>">
                        <td>
                            <strong>
                                <?php if ($repoPageAvailable): ?>
                                    <a href="<?= $this->url->href('RepoController', 'show', ['plugin' => 'Gumshoe', 'repo_id' => (int) $repo['id']]) ?>"><?= $e($repo['name']) ?></a>
                                <?php else: ?>
                                    <?= $e($repo['name']) ?>
                                <?php endif ?>
                            </strong>
                            <?= $repo['private'] ? '<span data-slot="pill">Private</span>' : '' ?>
                            <br><?= $e($repo['reason']) ?>
                        </td>
                        <td>
                            <?php if ($repo['outcome'] !== null): ?>
                                <span data-slot="pill"><?= $e($repo['outcome']) ?></span>
                            <?php endif ?>
                            <?php foreach ($repo['gaps'] as $verdict => $count): ?>
                                <?php if ($count > 0): ?>
                                    <span data-slot="pill"><?= $count ?> <?= $e($verdict) ?></span>
                                <?php endif ?>
                            <?php endforeach ?>
                        </td>
                        <td>
                            <select data-slot="control" name="repos[<?= (int) $repo['id'] ?>]" aria-label="Watch mode for <?= $e($fullName) ?>">
                                <?php foreach (['pin' => 'Pin', 'auto' => 'Auto', 'exclude' => 'Exclude'] as $mode => $label): ?>
                                    <option value="<?= $mode ?>" <?= $repo['mode'] === $mode ? 'selected' : '' ?>><?= $label ?></option>
                                <?php endforeach ?>
                            </select>
                        </td>
                    </tr>
                <?php endforeach ?>
            </tbody>
        </table>
    <?php endif ?>
</details>
