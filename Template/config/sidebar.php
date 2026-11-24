<?php if ($this->user->hasAccess('SourcesController', 'index')): ?>
    <li <?= $this->app->checkMenuSelection('SourcesController', '', 'Gumshoe') ?>>
        <?= $this->url->link('Gumshoe · Sources', 'SourcesController', 'index', ['plugin' => 'Gumshoe']) ?>
    </li>
<?php endif ?>
