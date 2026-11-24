# Gumshoe security model

Gumshoe reads lockfiles from GitHub repos, checks the packages against public advisory data, and writes tasks to
one Kanboard board. This document covers what it trusts, where the GitHub token goes, what leaves the server, and
what Gumshoe does not defend against.

## Assets

| Asset | Where it lives | Who must not get it |
|---|---|---|
| GitHub fine-grained PATs (one per owner) | Vault only, in an entry shared with Server; Gumshoe stores `vault://<entry>/token` | Everyone but GitHub's API |
| Private repo and package names | GitHub, Gumshoe's tables, the private findings board | OSV, CISA, GitHub's advisory API, public boards |
| The findings board | One Kanboard project chosen by an admin; it must be private | Non-members |

## Untrusted inputs

| Input | Why untrusted | Handling |
|---|---|---|
| Lockfiles (`composer.lock`, `package-lock.json`, `pnpm-lock.yaml`) and workflow YAML | Anyone who can push to a watched repo, or a compromised dependency's tooling, can plant one | Fetched through the GitHub API only; never cloned, installed or run. Caps: 10 MiB per file (14 MiB on the wire), 50 lockfiles per repo, 200,000 dependency rows per repo, JSON depth 64. YAML goes through vendored `symfony/yaml` 7.4.23 with no object, constant or custom-tag flags, at most 500,000 nodes and 1,000 alias references. A file over a cap or failing to parse is recorded as `too_large`, `too_many` or `parse_error` and makes the repo `partial`; nothing is skipped silently |
| `.npmrc` beside an npm or pnpm lockfile | Same as above | Read under the same caps; only `registry=` and `@scope:registry=` hosts are kept, never auth lines |
| GitHub API responses (repo lists, trees, blobs, pagination links) | Network input | Shape-checked; `Link` targets must stay on the same host and endpoint; repos not owned by the configured login are dropped |
| Advisory text from OSV, GitHub advisories and CISA KEV | Third-party text that ends up in tasks | Ids are checked against a fixed grammar. Summaries are escaped as plain text inside the Markdown Gumshoe builds. Links are built only from validated ids to `nvd.nist.gov`, `github.com/advisories` and `osv.dev`. Records with unexpected fields or shapes fail the query instead of being stored half-read |
| Admin input on the Sources page | Authenticated, but still form input | App-admin only on every route, POST with CSRF on every change, a settings revision check, and the target project must be private |

## Token path

1. An owner row holds a ref such as `vault://17/token`. The ref is checked against `vault://<int>/token` before Vault
   is called.
2. `Secrets\VaultTokenSource::forOwner()` calls `vaultSecrets->read('Gumshoe', $ref, $jobRef)` once per owner per scan
   slice and holds the returned `SecretValue` until the slice ends. Refusals are recorded as `refused:<reason>`
   (stored as `refused`); `rate_limited` backs off 60 seconds.
3. `Http\Client::send()` is the only caller of `SecretValue::reveal()`. It builds `Authorization: Bearer …` only for
   `gh.*` operations on `api.github.com` whose path belongs to that owner, builds it fresh for each hop, and wipes
   its copy with `sodium_memzero` afterwards.
4. Only `gh.blob` may follow a redirect, once, to `*.githubusercontent.com`, and that hop carries no
   `Authorization` header. cURL never follows redirects itself, uses HTTPS only, and ignores proxy environment
   variables (`CURLOPT_NOPROXY` `*`; v1 wires no proxy).
5. Response headers and bodies are scrubbed of the token before they leave the client. `HttpFailure` holds the
   operation, host, status and a short reason only. `Secrets\Redactor` removes `gh[pousr]_…` and `github_pat_…`
   strings from text written to tasks, and the Sources page refuses settings that contain one. Token parameters
   are marked `#[\SensitiveParameter]`, so traces don't print them.
6. Token expiry comes from GitHub's `github-authentication-token-expiration` response header: `expiring` 14 days
   ahead, `expired` on a 401, `unknown` without the header.

**Never stored:** the token (not in the database, settings, logs, run rows, exception messages, fixtures or task
text), `.npmrc` contents other than registry hosts, lockfile bodies (only parsed rows and blob SHAs), or response
headers. Run rows keep an exception class, never a message.

## Egress

Every request goes through `Http\Client`, which allows only these hosts over HTTPS on port 443. Every request
carries `User-Agent: Kanboard-Gumshoe/{version} (+{application_url})`, so each host below learns the Kanboard URL.

| Host | Operation | What is sent | Token |
|---|---|---|---|
| `api.github.com` | `gh.list`, `gh.repo`, `gh.branch`, `gh.tree`, `gh.blob` | GET only. Owner login, repo names, branch name, tree and blob SHAs in the path; `affiliation`/`type`/paging in the query | Yes, that owner's |
| `*.githubusercontent.com` | `gh.blob` redirect hop | GET of the signed URL GitHub returned | No |
| `api.github.com` | `gh.advisories` | GET `/advisories?type=malware&ecosystem={npm or composer}&per_page=100` plus paging. No package names: matching happens locally | No |
| `api.osv.dev` | `osv.querybatch` | POST `{"queries":[…]}`, each query `{"package":{"ecosystem":"Packagist" or "npm","name":…},"version":…}` or `{"commit":<40-hex SHA>}` for Actions, plus OSV's `page_token`. Only dependencies whose egress verdict is `public` | No |
| `api.osv.dev` | `osv.vulns` | GET `/v1/vulns/{id}` for advisory ids OSV returned | No |
| `www.cisa.gov` | `kev` | GET the KEV JSON feed, no parameters | No |
| `raw.githubusercontent.com` | `kev` | GET `cisagov/kev-data` mirror of the same feed, only when CISA fails | No |

**Egress verdicts (R1).** A dependency is `public` only with public-registry evidence in its lockfile (Composer
`notification-url` on packagist.org; npm `resolved` on registry.npmjs.org; pnpm's default registry with no
overriding `.npmrc`) or, for an Action pinned by SHA, a repo GitHub reported public in the same run. It must also
match the ecosystem's name grammar and no admin deny prefix (`denied`). Everything else is `private`, `denied` or
`unqueryable` and is shown as a coverage gap. Repo names go nowhere but GitHub.

## What Gumshoe does not defend

- **A compromised Kanboard server or admin account.** Whoever runs code as Kanboard can ask Vault for the token
  while Server sharing is on. Read-only PATs limit the damage.
- **A compromised GitHub account or PAT.** Gumshoe reads what GitHub returns.
- **Advisory feeds that are wrong or late.** No advisory means no task. OSV, GitHub and CISA are trusted for content.
- **Dependencies without a lockfile, `actions.lock`, Docker images, mutable Action tags.** Not scanned in v1; shown
  as coverage gaps where Gumshoe can see them.
- **Accepted residual risks:**
  - (a) **pnpm and outside registry config.** pnpm leaves out `tarball` when the default registry comes from
    outside the repo (a user's `~/.npmrc`, `NPM_CONFIG_REGISTRY` in CI). In a repo with no `.npmrc`, a private
    unscoped package then looks like an npmjs package and its name and version can go to OSV. The mitigation is
    the admin deny-prefix list on the Sources page: add the private package prefixes there.
  - (b) **Withdrawn or regrouped advisories.** A version that is still installed but whose advisory stops
    matching (withdrawn, or regrouped under another id) stays affected until a person dismisses the task.
    Gumshoe marks a repo fixed only on proof of absence (R2), and a missing match is not proof.
  - (c) **Early commit from a board listener.** A Kanboard event listener that calls PicoDb's
    `closeTransaction()` during a board write can commit a fenced batch early. The R5 recovery (claim, create with
    reference `gumshoe:finding:{id}`, recover by reference) brings the next run back to a consistent state.

## Security review gates

| Finding | Severity | Owner task | Test | Fix commit |
|---|---|---|---|---|
