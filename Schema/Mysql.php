<?php

namespace Kanboard\Plugin\Gumshoe\Schema;

use PDO;

const VERSION = 1;

function version_1(PDO $pdo): void
{
    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_settings (
            watch_id INTEGER NOT NULL PRIMARY KEY CHECK (watch_id = 1),
            window_days INTEGER NOT NULL DEFAULT 90,
            forks INTEGER NOT NULL DEFAULT 0,
            archived INTEGER NOT NULL DEFAULT 0,
            scanning INTEGER NOT NULL DEFAULT 1,
            hourly INTEGER NOT NULL DEFAULT 1,
            project_id INTEGER,
            deny_prefixes TEXT NOT NULL DEFAULT (''),
            revision INTEGER NOT NULL DEFAULT 0
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);
    $pdo->exec('INSERT INTO gumshoe_settings (watch_id) VALUES (1)');

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_owners (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            watch_id INTEGER NOT NULL DEFAULT 1,
            login VARCHAR(39) NOT NULL,
            kind VARCHAR(8) NOT NULL,
            enabled INTEGER NOT NULL DEFAULT 1,
            token_ref TEXT,
            token_status VARCHAR(16) NOT NULL DEFAULT 'missing',
            token_expires_at BIGINT,
            UNIQUE (watch_id, login)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_repos (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            owner_id INTEGER NOT NULL,
            name VARCHAR(100) NOT NULL,
            github_id BIGINT NOT NULL UNIQUE,
            mode VARCHAR(8) NOT NULL DEFAULT 'auto',
            private INTEGER NOT NULL DEFAULT 0,
            fork INTEGER NOT NULL DEFAULT 0,
            archived INTEGER NOT NULL DEFAULT 0,
            pushed_at BIGINT,
            default_branch TEXT,
            head_sha VARCHAR(64),
            tree_sha VARCHAR(64),
            outcome VARCHAR(16),
            last_complete_at BIGINT,
            gone_at BIGINT,
            UNIQUE (owner_id, name),
            FOREIGN KEY (owner_id) REFERENCES gumshoe_owners (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_lockfiles (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            repo_id INTEGER NOT NULL,
            path_hash VARCHAR(64) NOT NULL,
            path VARCHAR(1024) NOT NULL,
            blob_sha VARCHAR(64) NOT NULL,
            kind VARCHAR(16) NOT NULL,
            status VARCHAR(16) NOT NULL,
            parser_version INTEGER NOT NULL,
            last_complete_blob_sha VARCHAR(64),
            UNIQUE (repo_id, path_hash)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_deps (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            lockfile_id INTEGER NOT NULL,
            ecosystem VARCHAR(32) NOT NULL,
            name TEXT NOT NULL,
            version TEXT NOT NULL,
            scope VARCHAR(16) NOT NULL,
            source TEXT,
            query_type VARCHAR(16) NOT NULL DEFAULT 'none',
            egress VARCHAR(16) NOT NULL DEFAULT 'unqueryable',
            FOREIGN KEY (lockfile_id) REFERENCES gumshoe_lockfiles (id) ON DELETE CASCADE
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_dep_changes (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            run_id INTEGER NOT NULL,
            repo_id INTEGER NOT NULL,
            kind VARCHAR(16) NOT NULL,
            ecosystem VARCHAR(32),
            name TEXT,
            from_version TEXT,
            to_version TEXT,
            path TEXT,
            created_at BIGINT NOT NULL
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_groups (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            primary_id VARCHAR(255) NOT NULL,
            cvss_max DOUBLE PRECISION,
            malware INTEGER NOT NULL DEFAULT 0,
            kev INTEGER NOT NULL DEFAULT 0,
            merged_into INTEGER
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_group_aliases (
            alias VARCHAR(255) NOT NULL UNIQUE,
            group_id INTEGER NOT NULL,
            FOREIGN KEY (group_id) REFERENCES gumshoe_groups (id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_advisory_cache (
            source VARCHAR(16) NOT NULL,
            advisory_id VARCHAR(255) NOT NULL,
            modified VARCHAR(64),
            body MEDIUMTEXT NOT NULL,
            fetched_at BIGINT NOT NULL,
            UNIQUE (source, advisory_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_findings (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            group_id INTEGER NOT NULL,
            ecosystem VARCHAR(32) NOT NULL,
            package VARCHAR(512) NOT NULL,
            task_id INTEGER,
            project_id INTEGER,
            priority VARCHAR(8) NOT NULL DEFAULT 'normal',
            status VARCHAR(16) NOT NULL DEFAULT 'open',
            closed_by_gumshoe_at BIGINT,
            reopened_by_person_at BIGINT,
            observed_priority VARCHAR(8),
            observed_malware SMALLINT,
            observed_kev SMALLINT,
            observed_status VARCHAR(16),
            last_synced_at BIGINT,
            UNIQUE (group_id, ecosystem, package)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_finding_repos (
            finding_id INTEGER NOT NULL,
            repo_id INTEGER NOT NULL,
            subtask_id INTEGER,
            state VARCHAR(8) NOT NULL DEFAULT 'unknown',
            ever_affected INTEGER NOT NULL DEFAULT 0,
            UNIQUE (finding_id, repo_id)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_exposures (
            finding_id INTEGER NOT NULL,
            repo_id INTEGER NOT NULL,
            lockfile_id INTEGER NOT NULL,
            version VARCHAR(191) NOT NULL,
            active INTEGER NOT NULL DEFAULT 1,
            first_seen BIGINT NOT NULL,
            last_seen BIGINT NOT NULL,
            UNIQUE (finding_id, repo_id, lockfile_id, version)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_pending (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            run_id INTEGER NOT NULL,
            query_type VARCHAR(16) NOT NULL,
            ecosystem VARCHAR(32) NOT NULL,
            name VARCHAR(512) NOT NULL,
            version VARCHAR(191) NOT NULL,
            egress VARCHAR(16) NOT NULL DEFAULT 'unqueryable',
            state VARCHAR(16) NOT NULL DEFAULT 'pending',
            page_token TEXT,
            retry_at BIGINT,
            UNIQUE (run_id, query_type, ecosystem, name, version)
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_state (
            name VARCHAR(32) NOT NULL PRIMARY KEY,
            holder VARCHAR(128),
            lease_until BIGINT NOT NULL DEFAULT 0,
            run_id INTEGER
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);
    $pdo->exec("INSERT INTO gumshoe_state (name) VALUES ('writer')");

    $pdo->exec(<<<'SQL'
        CREATE TABLE gumshoe_runs (
            id INT NOT NULL AUTO_INCREMENT PRIMARY KEY,
            job VARCHAR(32) NOT NULL,
            `trigger` VARCHAR(16) NOT NULL,
            phase VARCHAR(16) NOT NULL DEFAULT 'discover',
            position TEXT,
            status VARCHAR(8) NOT NULL DEFAULT 'more',
            counts TEXT NOT NULL DEFAULT ('{}'),
            exception_class VARCHAR(255),
            retry_at BIGINT,
            started_at BIGINT NOT NULL,
            finished_at BIGINT
        ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_bin ROW_FORMAT=DYNAMIC
        SQL);
}
