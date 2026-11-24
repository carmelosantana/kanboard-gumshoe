# Gumshoe

Gumshoe is a Kanboard plugin for tracking known dependency vulnerabilities and malware in GitHub lockfiles. It is designed to keep one task per advisory and package on a private Kanboard board, with one subtask for each affected repository.

The v1 scaffold defines the database schema and plugin metadata. Scanning and board synchronization are still in development.

## Requirements

- Kanboard 1.2.47 or later and PHP 8.4 or later.
- Vault with Server sharing enabled for GitHub tokens. Gumshoe stores Vault references.
- Foreman is optional and provides scheduled scans.

## Development

Run the test suite from the plugin checkout with `../testing/run-plugin-tests.sh Gumshoe`. The default harness uses SQLite. The plugin also includes schemas for MySQL/MariaDB and PostgreSQL.

Gumshoe is licensed under the [MIT License](LICENSE).
