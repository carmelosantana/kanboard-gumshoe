# Test fixtures

Recorded 2026-11-24 (UTC) from public sources only. Every GitHub request was plain `curl` with no
`Authorization` header (the unauthenticated API, 60 requests/hour). Tests replay these files and
never touch the network. Files marked **hand-made** were written by hand (or by a throwaway
generator, not committed) in the shape of the real responses next to them.

Pinned commits used below:

| Repo | Commit | How it was found |
|---|---|---|
| `actions/hello-world-javascript-action` | `eb62a644ef35d9335d22bb625da7ce94314f3ae4` (2020-10-01, last lockfile v1), `a8dd2c1169d0de038bb630cf188c6a66d3dcecd6` (2022-04-05, first lockfile v2) | `git log -- package-lock.json` in a `--filter=blob:none` clone |
| `npm/cli` | `787f1520fa412e91a5792468f1c7f25b166867a6` | `HEAD` of a depth-1 blobless clone |
| `pnpm/pnpm` | `afe8ecef1f24812845b699c141d52643d1524079` (tag `v8.15.9`), `4396ef2399d43c3ced772b05e8f18add632c4bde` (`HEAD`) | `git fetch --depth 1 origin tag v8.15.9`, `HEAD` of a depth-1 clone |
| `composer/composer` | `edc2b0dbc63b9fad29b0b72311fe7247ffae33e1` | `HEAD` of a blobless clone |
| `actions/checkout` | `b4ffde65f46336ab88eb53be808477a3936bae11` (`v4.1.1`), `722adc63f1aa60a57ec37892e133b1d319cae598` (`v2.0.0`) | `git ls-remote https://github.com/actions/checkout 'refs/tags/v4.1.1*' 'refs/tags/v2.0.0*'` |

`RAW=https://raw.githubusercontent.com`

## github/

| File | Source command | Notes |
|---|---|---|
| `repos-list.json`, `repos-list.headers.txt` | `curl -sS -D repos-list.headers.txt -o repos-list.json 'https://api.github.com/users/carmelosantana/repos?per_page=5&type=owner'` | 5 public repos; headers carry `link` (`rel="next"`, `rel="last"`) and `x-ratelimit-*` |
| `repo.json`, `repo.headers.txt` | `curl -sS -D repo.headers.txt -o repo.json https://api.github.com/repos/carmelosantana/ai-context-builder` | default branch `main` |
| `branch.json`, `branch.headers.txt` | `curl -sS -D branch.headers.txt -o branch.json https://api.github.com/repos/carmelosantana/ai-context-builder/branches/main` | commit `0bfcd66f…`, tree `e705c248…` |
| `tree.json`, `tree.headers.txt` | `curl -sS -D tree.headers.txt -o tree.json 'https://api.github.com/repos/carmelosantana/ai-context-builder/git/trees/e705c2485ff336065ac514f02bdc9ad06d8b8690?recursive=1'` | 9 entries, `truncated: false` |
| `blob-raw.bin`, `blob-raw.headers.txt` | `curl -sS -D blob-raw.headers.txt -o blob-raw.bin -H 'Accept: application/vnd.github.raw+json' https://api.github.com/repos/carmelosantana/ai-context-builder/git/blobs/967a026414ede63037a7626a8a5b7d89a1622626` | raw bytes of `composer.json`; `git hash-object blob-raw.bin` = the blob sha; `content-type: text/plain` |
| `error-403-secondary.json`, `.headers.txt` | **hand-made** | secondary rate limit, 403, **no** `Retry-After`, `x-ratelimit-remaining` non-zero |
| `error-403-ratelimit.json`, `.headers.txt` | **hand-made** | primary limit: 403, `x-ratelimit-remaining: 0`, `x-ratelimit-reset: 1795501200` (IP is TEST-NET `203.0.113.7`) |
| `error-404.json`, `.headers.txt` | **hand-made** | `Not Found` |
| `error-409-empty.json`, `.headers.txt` | **hand-made** | `Git Repository is empty.` from the trees endpoint |
| `tree-truncated.json` | **hand-made** | tree with `"truncated": true`, placeholder shas, owner `example-owner` |
| `token-expiration.headers.txt` | **hand-made** | 200 headers with `github-authentication-token-expiration: 2026-12-31 00:00:00 UTC` |

## lockfiles/

| File | Source command | Notes |
|---|---|---|
| `composer.lock` | `curl -sSf -o composer.lock $RAW/composer/composer/edc2b0dbc63b9fad29b0b72311fe7247ffae33e1/composer.lock` | has `packages-dev` and `notification-url` (`https://packagist.org/downloads/`); untrimmed |
| `package-lock.v1.json` | `curl -sSf -o package-lock.v1.json $RAW/actions/hello-world-javascript-action/eb62a644ef35d9335d22bb625da7ce94314f3ae4/package-lock.json` | `lockfileVersion: 1`, nested `dependencies`, `resolved` URLs on registry.npmjs.org |
| `package-lock.v2.json` | `curl -sSf -o package-lock.v2.json $RAW/actions/hello-world-javascript-action/a8dd2c1169d0de038bb630cf188c6a66d3dcecd6/package-lock.json` | `lockfileVersion: 2`, `packages` + `dependencies`, `resolved` URLs |
| `package-lock.v3-workspace.json` | `curl -sSf -o package-lock.v3-workspace.json $RAW/npm/cli/787f1520fa412e91a5792468f1c7f25b166867a6/workspaces/arborist/test/fixtures/workspaces-with-overrides/package-lock.json` | `lockfileVersion: 3`, workspace `ws` (`link: true` + member entry), one `resolved` URL |
| `package-lock.v3-alias.hand.json` | **hand-made** | v3 alias: root `"string-width-cjs": "npm:string-width@^4.2.0"`, `node_modules/string-width-cjs` with `"name": "string-width"` (shape and integrity copied from real npm output). No small real lockfile with an alias was found |
| `package-lock.v1-alias.hand.json` | **hand-made** | v1 alias: `"version": "npm:string-width@4.2.3"` |
| `pnpm-lock.v6-workspace.yaml` | `curl -sSf -o pnpm-lock.v6-workspace.yaml $RAW/pnpm/pnpm/afe8ecef1f24812845b699c141d52643d1524079/__fixtures__/workspace-external-depends-deep/pnpm-lock.yaml` | `lockfileVersion: '6.0'`, `importers`, keys `/@pnpm.e2e/external-depend-on-internal-dep@1.0.0`, `/is-positive@1.0.0`, a `link:` dep |
| `pnpm-lock.v6-peers.yaml` | `curl -sSf -o pnpm-lock.v6-peers.yaml $RAW/pnpm/pnpm/afe8ecef1f24812845b699c141d52643d1524079/pkg-manager/headless/test/fixtures/reinstall-peer-deps/pnpm-lock.yaml` | v6, scoped keys with peer suffixes `/@pnpm.e2e/abc@1.0.0(@pnpm.e2e/peer-a@1.0.1)(…)`, all `dev: true` |
| `pnpm-lock.v9-workspace.yaml` | `curl -sSf -o pnpm-lock.v9-workspace.yaml $RAW/pnpm/pnpm/4396ef2399d43c3ced772b05e8f18add632c4bde/pnpm/crates/cli/tests/fixtures/with-peer-and-real-dep/pnpm-lock.yaml` | v9, `importers` (`.`, `packages/pkg-a`, `packages/pkg-b`), `packages` + `snapshots`; despite the directory name it has no peer suffixes (no small real v9 file with peer suffixes was found) |
| `pnpm-lock.v9-v13-multidoc.yaml` | `curl -sSf -o pnpm-lock.v9-v13-multidoc.yaml $RAW/pnpm/pnpm/4396ef2399d43c3ced772b05e8f18add632c4bde/pnpm-lock.yaml` | real multi-document file: doc 1 is a v9 env lockfile (`packageManagerDependencies`), doc 2 is `"lockfileVersion": "13.0"` in JSON-like flow style with tabs and trailing commas. Untrimmed (253 KB). pnpm `v11.29.0` has the same layout. No real file with two v9 documents small enough to keep was found |
| `pnpm-lock.v9-multidoc.hand.yaml` | **hand-made** from real parts: `{ sed -n 1,176p pnpm-lock.v9-v13-multidoc.yaml; echo '---'; cat pnpm-lock.v9-workspace.yaml; }` | two v9 documents: the real env-lockfile doc plus the real `pnpm-lock.v9-workspace.yaml` |
| `workflow-mixed.hand.yml` | **hand-made** from real `uses:` lines | `actions/checkout@b4ffde65…` (40-hex, real v4.1.1 commit), `actions/setup-node@v4`, `github/codeql-action/init@v4` (sub-path), `docker://rhysd/actionlint:1.7.7`, `./.github/actions/local-setup`, and a job-level reusable workflow `slsa-framework/slsa-github-generator/.github/workflows/generator_generic_slsa3.yml@v2.0.0`. No single small real workflow had all four |

**`actions.lock`: not found.** Probed `$RAW/<repo>/HEAD/.github/workflows/actions.lock` (and `actions.lock`, `.github/actions.lock`) on `github/gh-aw`, `github/docs`, `actions/checkout`, `actions/runner`, `actions/toolkit`, `cli/cli`, `github/codeql-action`, `actions/setup-node`, `actions/cache`, `actions/upload-artifact`, `microsoft/vscode`, `github/github-mcp-server`: all 404. The only lock-like file seen was `github/gh-aw`'s `.github/aw/actions-lock.json` (a different tool's format, `{"entries": {"owner/repo@ref": {"repo","version","sha","inputs"}}}`, 103 KB); not recorded.

## hostile/ (all **hand-made**)

Generated by a throwaway Python script run with `python3 -I`, not committed. What each tests:

| File | What it is |
|---|---|
| `package-lock-12MiB.json.gz` | valid `lockfileVersion: 3` JSON of exactly 12,582,912 bytes (12 MiB) when decompressed: 72,816 `node_modules/pkg-NNNNNN` entries, space-padded to the exact size. Stored gzip (`mtime=0`); **tests decompress it** (`gzdecode(file_get_contents(...))`). Over the 10 MiB decoded cap, under the 14 MiB wire cap |
| `yaml-php-object.yaml` | `settings: !php/object 'O:8:"stdClass":…'` |
| `yaml-php-const.yaml` | `autoInstallPeers: !php/const PHP_INT_MAX` |
| `yaml-binary.yaml` | `blob: !!binary <base64>` |
| `yaml-alias-bomb.yaml` | billion laughs: 9 anchors `a`…`i`, each 9 aliases of the previous (73 aliases, 9^9 leaves when expanded); trips the post-parse node cap, not the alias-count cap |
| `yaml-alias-count.yaml` | 1,100 `*a` aliases of one scalar; trips the pre-parse alias/anchor count cap (≤ 1,000) |
| `yaml-block-scalar-dashes.yaml` | v9 lockfile whose `deprecated: |` block scalar contains indented `---` lines; is one document |
| `json-nested-100.json` | `{"lockfileVersion":3,"packages":{"":{"a":{"a":…}}}}`, 100 nested `a` objects (over depth 64) |
| `package-lock-script-name.json` | v3 lockfile with package name `</script><img src=x>` |
| `package-lock-token-shaped.json` | v3 lockfile with package name `fake-ghp_` + `A1`×18 (36 chars) + `-github_pat_` + `A1`×41 (82 chars). Obviously fake, not a real token |

Note recorded while checking: with the vendored `symfony/yaml` and flags `0`, `Yaml::parse()` does **not** throw on these tags: `!php/object` and `!php/const` come back as `null` and `!!binary` is decoded to its string. A `parse_error` outcome has to come from Gumshoe itself.

## osv/

| File | Source command | Notes |
|---|---|---|
| `querybatch.request.json` | written by hand (the request body) | npm `lodash@4.17.20`, Packagist `guzzlehttp/guzzle@7.4.0`, npm `flatmap-stream@0.1.1` (malware), npm `is-positive@3.1.0` (clean), commit `722adc63…` (actions/checkout v2.0.0), Packagist `facade/ignition@2.5.1` (CVE-2021-3129, in KEV) |
| `querybatch.response.json`, `.headers.txt` | `curl -sS -D querybatch.response.headers.txt -o querybatch.response.json -H 'Content-Type: application/json' --data-binary @querybatch.request.json https://api.osv.dev/v1/querybatch` | results per query: 4, 14, 3 (incl. `MAL-2025-20690`), `{}`, `{}`, 1 |
| `vulns/<id>.json` (22 files) | `for id in <every id in querybatch.response.json>; do curl -sS -o vulns/$id.json https://api.osv.dev/v1/vulns/$id; done` | every id the batch returned |
| `querybatch-paged.request.json`, `querybatch-paged.response.json` | `curl -sS -o querybatch-paged.response.json -H 'Content-Type: application/json' --data-binary @querybatch-paged.request.json https://api.osv.dev/v1/querybatch` with `{"queries":[{"package":{"name":"Kernel","ecosystem":"Linux"},"version":"5.4.0"}]}` | real: result has `next_page_token` and **no** `vulns` |
| `querybatch-paged-2.request.json`, `querybatch-paged-2.response.json` | same query plus `"page_token": "<token from page 1>"` | real: page 2 again has only a new `next_page_token`. OSV can return empty pages with a token; ids from paged results were not fetched |

## ghsa/

| File | Source command | Notes |
|---|---|---|
| `malware-npm.json`, `malware-npm.headers.txt` | `curl -sS -D malware-npm.headers.txt -o malware-npm.json 'https://api.github.com/advisories?type=malware&ecosystem=npm&per_page=5'` | 5 public malware advisories; `link` has `rel="next"` with an `after=` cursor |
| `prerelease-range.json`, `prerelease-range.headers.txt` | `curl -sS -D prerelease-range.headers.txt -o prerelease-range.json https://api.github.com/advisories/GHSA-ggv3-7p47-pfv8` | real reviewed advisory for npm `next`; ranges `>= 16.0.0-beta.0, < 16.1.7` and `>= 9.5.0, < 15.5.13` |

## kev/

| File | Source command | Notes |
|---|---|---|
| `known_exploited_vulnerabilities.json` | `curl -sS -o kev-full.json https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`, then trimmed with Python: top-level fields kept (`catalogVersion` 2026.11.23), `vulnerabilities` = the first 19 entries + `CVE-2021-3129`, `count` set to 20, re-serialised with 4-space indent | `CVE-2021-3129` is the alias of OSV `GHSA-4qwp-7c67-jmcc` (`facade/ignition`) in `osv/vulns/`. None of the other OSV CVEs are in KEV |
| `invalid.json` | **hand-made** | `{}` (no newline) |
