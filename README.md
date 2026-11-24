# Gumshoe

Gumshoe watches the lockfiles in your GitHub repos and tells you, on a Kanboard board, when one of them pins a
package with a known vulnerability or malware.

Each day it reads `composer.lock`, `package-lock.json`, `pnpm-lock.yaml` and `.github/workflows/*.yml` from every
watched repo's default branch through the GitHub API (no clones, no installs), records what changed, and checks every
public package against OSV (CVEs and `MAL-*` malware), GitHub's malware advisories and CISA's Known Exploited
Vulnerabilities list. An hourly recheck catches newly published malware for packages it already knows.

## Requirements

- Kanboard 1.2.47 or later, PHP 8.4 or later.
- Vault 1.1.0 or later with **Server sharing** on. Gumshoe keeps
  GitHub tokens only in Vault and stores `vault://` references; it does not scan without it.
- Foreman is recommended to run the scans on a schedule.

## Setup

1. For each GitHub owner (your account and each org), create a **fine-grained personal access token**, read-only:
   Metadata and Contents, on all of that owner's repos. An org may need to approve it.
2. In Vault, save the token in an entry field named `token`, share the entry with **Server**, and grant consumer
   `Gumshoe`.
3. Create a **private** project for findings (for example "CVE Hunter"). Gumshoe will not write to a public one.
4. Open **Settings → Gumshoe → Sources** as an admin: choose the findings board, enable owners, pick each owner's Vault
   entry, and set which repos are watched (recently pushed repos are watched by default; pin or exclude any repo).
   Add your private package prefixes to **Deny prefixes** so they are never sent to OSV.
5. Add one crontab line on the Kanboard host:

   ```
   * * * * * cd /path/to/kanboard && ./cli foreman:run     # with Foreman
   * * * * * cd /path/to/kanboard && ./cli gumshoe:scan    # without Foreman
   ```

   Without a crontab, Kanboard page visits start due scans after the response is sent, in short slices.

Rotate each token before it expires; Sources marks it `expiring` 14 days ahead.

## Findings on the board

- One task per advisory and package, titled `[Gumshoe] {package} — {advisory id} ({n} repos)`, with one subtask per
  affected repo (`{owner}/{repo}`). CVE, GHSA, OSV and MAL ids for the same problem are merged into one task.
- Priority: Urgent for malware or KEV, High for CVSS 7 or more, Normal for medium or unknown, Low for low.
- A repo's subtask is ticked when a complete scan shows the package is gone or upgraded, and the task closes when
  every repo is fixed. A repo Gumshoe could not fully scan stays affected.
- Subtask status is derived from the scan on every sync, so ticking a subtask for a repo that is still affected is
  undone. To dismiss a finding, close the task. It reopens only if things get worse: higher priority, newly malware
  or KEV, or a new repo affected.
- Run history is on **Settings → Gumshoe → Run log**; each repo has a page with its dependencies, changes and
  findings.

## Not in v1

AI summaries, repos with manifests but no lockfile, `.github/workflows/actions.lock`, and Docker images. These show
as coverage gaps where Gumshoe can see them.

## Security

See [docs/security.md](docs/security.md) for the threat model, the token path and exactly what is sent to which host.

## Development

Run the tests from the plugin checkout with `../testing/run-plugin-tests.sh Gumshoe`. `Test/VaultIntegrationTest.php`
runs against Vault's real consumer API; set `GUMSHOE_REQUIRE_VAULT=1` to make it fail instead of skip when that API
is missing.

Gumshoe is licensed under the [MIT License](LICENSE).
