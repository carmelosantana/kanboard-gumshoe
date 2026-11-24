# Vendored dependencies

Gumshoe is buildless: `vendor/` is committed and shipped in the release zip. The one direct
dependency is `symfony/yaml` (pnpm-lock and GitHub Actions parsing). Vetted 2026-11-23 with
`/powerup:supply-chain`.

## Install command

```bash
composer require symfony/yaml:7.4.23 --no-scripts --no-plugins --no-interaction
```

`composer.json` pins `config.platform.php` to 8.4.0, sets `allow-plugins: false` and
`optimize-autoloader: true`. Nothing in `vendor/` is hand-edited; `vendor/composer/installed.json`
and the class map match `composer.lock`. To update: re-vet, re-run the command with the new exact
version, and update this file in the same commit.

## Packages

| Package | Version | Released | Upstream tag → commit | Dist archive sha256 | Licence |
|---|---|---|---|---|---|
| `symfony/yaml` | v7.4.23 | 2026-11-04 | `v7.4.23` → `1e601207ffe627a2e621faa9d661f1d32dcf1cec` | `15198d312d2de119291694beeb4f16e62a4398e37c2a17bd80c77baa0e87af0d` | MIT |
| `symfony/polyfill-ctype` | v1.37.0 | 2026-04-10 | `v1.37.0` → `141046a8f9477948ff284fa65be2095baafb94f2` | `922b0c6b24d1bcb6447d051edc1fc4526bcca5f88ddc4a27d885507872ceecc1` | MIT |
| `symfony/deprecation-contracts` | v3.8.1 | 2026-09-16 | `v3.8.1` → `feb1edf4e546af3b85c5caebe8359a20db230ca3` | `284796ef0bf256f751e424a1f14763bc459cfe9fada8a0eb5eb3d2762587be0e` | MIT |

`deprecation-contracts` is a hard requirement of `symfony/yaml` 7.4 that the plan did not list; it
is one function (`trigger_deprecation`) behind a `function_exists` guard.

## Vet record

| Check | Result |
|---|---|
| Version choice | Latest 7.x stable at least two weeks old (19 days at vet time). 7.x over 8.x: 8.x requires PHP ≥ 8.4.1; 7.4 requires ≥ 8.2 and is the LTS line |
| Dist integrity | Packagist publishes no `dist.shasum` for these GitHub zipballs; the lock's `dist.reference` equals the commit that `git ls-remote https://github.com/symfony/<pkg> refs/tags/<tag>^{}` resolves, and the sha256 above is of the archive downloaded from that reference |
| Maintainers | Packagist: `fabpot` (Symfony project lead), repository `github.com/symfony/*`, not abandoned |
| Advisories | OSV `v1/query` for each exact version: none. `composer audit` (run by `require`): none. The only `symfony/yaml` advisories are for 2.0.x (CVE-2013-1348 and siblings) |
| Install scripts | None in any package (`scripts` absent); Composer ran with `--no-scripts --no-plugins` |
| Binaries | `vendor/bin/yaml-lint` (proxy to `symfony/yaml/Resources/bin/yaml-lint`); CLI-only, never loaded by the plugin |
| Code scan | No `eval`, `exec`, `shell_exec`, `curl_*` or `fsockopen` under `vendor/symfony` |
| Size | 339 KiB |

## Coexistence with Kanboard core and other plugins

Kanboard's own `vendor/` already ships `symfony/polyfill-ctype` and `symfony/deprecation-contracts`.
Gumshoe keeps its copies in the lockfile and vendored so its loader and `installed.json` stay
consistent. They are inert when core's are loaded first:

- Composer's `files` autoload records each file by a package-derived identifier in
  `$GLOBALS['__composer_autoload_files']`; an identifier already loaded by core's autoloader is
  skipped.
- `polyfill-ctype` defines functions only behind `function_exists` (and PHP's `ctype` extension is
  normally loaded, so none are defined at all).
- `deprecation-contracts` defines `trigger_deprecation` only behind `function_exists`.

`symfony/yaml` itself is not in Kanboard core and not vendored by any other suite plugin
(checked: no other `*/composer.lock` in the harness lists it).
