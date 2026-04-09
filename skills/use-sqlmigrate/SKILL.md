---
name: use-sqlmigrate
description: Database migration tools for Go projects. Use when writing migrations, running sql-migrate CLI, embedding migrations in Go apps, or setting up new database schemas. Covers PostgreSQL, MySQL/MariaDB, SQLite, SQL Server.
depends: [go-stack]
---

## Overview

sqlmigrate is a feature-branch-friendly SQL migration system with two modes:

1. **CLI** (`sql-migrate`) — generates shell scripts that pipe to `sh`
2. **Go library** (`sqlmigrate` + backend) — embed migrations in Go binaries

Both use the same migration file format and `_migrations` tracking table.

## Focused skills

| Skill | When to use |
|-------|-------------|
| `use-sql-migrate-cli` | CLI tool: init, create, up, down, sync, status |
| `use-sql-migrate-golang` | Go library: embed migrations, Migrator interface, auto-migrate on startup |
| `use-sql-migrate-postgres` | PostgreSQL: pgx connection, schema multi-tenancy, PGOPTIONS |
| `use-sql-migrate-mysql` | MySQL/MariaDB: multiStatements DSN, MY_CNF, mariadb vs mysql |
| `use-sql-migrate-sqlite` | SQLite: foreign keys pragma, modernc.org/sqlite driver |
| `use-sql-migrate-sqlserver` | SQL Server: sqlcmd, TDS 8.0 encryption, SQLCMD* env vars |

## Migration file format

```
<yyyy-mm-dd>-<number>_<name>.<up|down>.sql
2026-04-05-001000_create-todos.up.sql
2026-04-05-001000_create-todos.down.sql
```

- Numbers increment by 1000 (allows inserting between)
- Initial migration: `0001-01-01-001000_init-migrations`
- Each `.up.sql` MUST end with `INSERT INTO _migrations (name, id) VALUES ('<name>', '<8-hex-id>');`
- Each `.down.sql` MUST end with `DELETE FROM _migrations WHERE id = '<8-hex-id>';`

## Key design decisions

- **Feature-branch friendly**: no sequential numbering, no conflicts
- **ID-based matching**: migrations matched by 8-char hex ID, not name — safe to rename
- **Shell-first CLI**: generates reviewable scripts, never executes directly
- **Separate Go modules**: each backend is its own module to avoid pulling unnecessary drivers
