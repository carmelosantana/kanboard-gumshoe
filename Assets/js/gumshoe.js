KB.component('gumshoe-sources', function (form) {
    this.render = function () {
        var search = form.querySelector('[data-repo-search]');
        var filter = form.querySelector('[data-repo-filter]');
        var project = form.querySelector('#gumshoe-project');
        var noResults = form.querySelector('[data-no-results]');
        var initial = new Map(new FormData(form));
        var owners = Array.from(form.querySelectorAll('[data-owner-status]')).map(function (owner) {
            return {
                element: owner,
                rows: Array.from(owner.querySelectorAll('[data-repo]')).map(function (row) {
                    return {element: row, data: JSON.parse(row.dataset.repo)};
                })
            };
        });

        function applyFilter(needsToken) {
            var query = search.value.trim().toLowerCase();
            var mode = filter.value;
            var filtering = query !== '' || mode !== 'all';
            var anyMatch = false;
            owners.forEach(function (owner) {
                var matching = false;
                owner.rows.forEach(function (row) {
                    var repo = row.data;
                    var matchesMode = mode === 'all' || (mode === 'watching' && repo.watched)
                        || (mode === 'not-watching' && !repo.watched) || repo.mode === mode;
                    var visible = matchesMode && repo.name.toLowerCase().includes(query);
                    row.element.hidden = !visible;
                    matching = matching || visible;
                });
                owner.element.hidden = filtering && !matching;
                if (needsToken) {
                    owner.element.open = owner.element.dataset.ownerStatus !== 'ok';
                } else if (filtering) {
                    owner.element.open = matching;
                }
                anyMatch = anyMatch || matching;
            });
            noResults.hidden = !filtering || anyMatch;
        }

        search.addEventListener('input', function () { applyFilter(false); });
        filter.addEventListener('change', function () { applyFilter(false); });
        project.addEventListener('change', function () {
            form.querySelector('#gumshoe-public-board').hidden = project.selectedOptions[0].dataset.public !== '1';
        });

        var tokenLink = document.querySelector('.gumshoe-sources [data-needs-token]');
        if (tokenLink) {
            tokenLink.addEventListener('click', function () {
                search.value = '';
                filter.value = 'all';
                applyFilter(true);
            });
        }

        form.addEventListener('formdata', function (event) {
            initial.forEach(function (value, name) {
                var submitted = event.formData.getAll(name);
                if (/^(settings|owners|repos)\[/.test(name) && submitted[submitted.length - 1] === value) {
                    event.formData.delete(name);
                }
            });
        });
    };
});
