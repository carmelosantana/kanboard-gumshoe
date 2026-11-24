# Changelog

## 1.0.0 — 2026-11-24

First release.

- Watches GitHub repos across a user account and orgs: recently pushed repos by default, with per-repo pin and
  exclude, and forks, archived repos and owners switchable.
- Reads `composer.lock`, `package-lock.json` (v1–3), `pnpm-lock.yaml` (v6+ and workspaces) and GitHub Actions
  `uses:` refs through the GitHub API, under size, count and YAML limits, and records what changed on every scan.
- Matches dependencies against OSV (including `MAL-*` malware), GitHub's malware advisories and CISA KEV, with an
  hourly OSV recheck for known packages.
- Sends only packages with public-registry evidence to OSV; private, denied and unqueryable packages show as coverage
  gaps. Admin deny prefixes.
- One task per advisory group and package on a private board, one subtask per affected repo; repos are marked fixed
  only after a complete scan. Closing a task dismisses it; it reopens only on escalation. Crash-safe task creation
  and alias merges keep the active task.
- GitHub tokens are read from Vault's consumer API (consumer `Gumshoe`, field `token`) and never stored.
- One fenced writer lease with resumable phases; runs via Foreman (`gumshoe.inventory`, `gumshoe.osv-recheck`), the
  `gumshoe:scan` command or a page-visit fallback.
- Settings → Gumshoe: Sources, Run log and per-repo pages.
- Schemas for SQLite, MySQL/MariaDB and PostgreSQL.
