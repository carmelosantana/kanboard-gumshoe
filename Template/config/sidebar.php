<?php if ($this->user->hasAccess('SourcesController', 'index')): ?>
    <li <?= $this->app->checkMenuSelection('SourcesController', '', 'Gumshoe') ?: $this->app->checkMenuSelection('RepoController', 'show', 'Gumshoe') ?>>
        <?= $this->url->link('Gumshoe · Sources', 'SourcesController', 'index', ['plugin' => 'Gumshoe']) ?>
    </li>
<?php endif ?>
<?php if ($this->user->hasAccess('RunController', 'index')): ?>
    <li <?= $this->app->checkMenuSelection('RunController', 'index', 'Gumshoe') ?>>
        <?= $this->url->link('Gumshoe · Run log', 'RunController', 'index', ['plugin' => 'Gumshoe']) ?>
    </li>
<?php endif ?>
