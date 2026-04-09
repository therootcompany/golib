---
name: use-sql-migrate-cli
description: sql-migrate CLI tool for database migrations. Use when initializing migrations, creating migration files, running up/down, checking status, or generating migration scripts. Covers psql, mariadb, mysql, sqlite, sqlcmd.
depends: [use-sqlmigrate]
---

## Install

```sh
webi go
go install github.com/therootcompany/golib/cmd/sql-migrate/v2@latest
```

## Commands

### init

```sh
sql-migrate -d ./sql/migrations/ init --sql-command <psql|mariadb|mysql|sqlite|sqlcmd>
```

Creates: migrations directory, `0001-01-01-001000_init-migrations.{up,down}.sql`,
`migrations.log`, `_migrations.sql` query file.

MUST: Run the generated init script to create the `_migrations` table:

```sh
sql-migrate -d ./sql/migrations/ up | sh
```

### create

```sh
sql-migrate -d ./sql/migrations/ create add-user-tables
```

Generates a canonically-named up/down pair with a random 8-hex-char ID:

```
2026-04-09-001000_add-user-tables.up.sql
2026-04-09-001000_add-user-tables.down.sql
```

If files for today already exist, the number increments by 1000.

### up / down

```sh
# apply ALL pending migrations
sql-migrate -d ./sql/migrations/ up | sh

# apply next 2 pending
sql-migrate -d ./sql/migrations/ up 2 | sh

# roll back 1 (default)
sql-migrate -d ./sql/migrations/ down | sh

# roll back 3
sql-migrate -d ./sql/migrations/ down 3 | sh
```

Output is a shell script. Review before piping to `sh`.

### status

```sh
sql-migrate -d ./sql/migrations/ status
```

Shows applied (reverse order) and pending migrations. Does not execute anything.

### sync

```sh
sql-migrate -d ./sql/migrations/ sync | sh
```

Reloads `migrations.log` from the database. Run after upgrading sql-migrate.

### list

```sh
sql-migrate -d ./sql/migrations/ list
```

Lists all up/down migration files found.

## Options

| Flag | Default | Purpose |
|------|---------|---------|
| `-d <dir>` | `./sql/migrations/` | Migrations directory |
| `--sql-command` | `psql` | SQL command template (init only) |
| `--migrations-log` | `../migrations.log` | Log file path relative to migrations dir (init only) |

## SQL command aliases

| Alias | Expands to |
|-------|-----------|
| `psql`, `postgres`, `postgresql`, `pg`, `plpgsql` | `psql "$PG_URL" -v ON_ERROR_STOP=on --no-align --tuples-only --file %s` |
| `mariadb` | `mariadb --defaults-extra-file="$MY_CNF" --silent --skip-column-names --raw < %s` |
| `mysql`, `my` | `mysql --defaults-extra-file="$MY_CNF" --silent --skip-column-names --raw < %s` |
| `sqlite`, `sqlite3`, `lite` | `sqlite3 "$SQLITE_PATH" < %s` |
| `sqlcmd`, `mssql`, `sqlserver` | `sqlcmd --exit-on-error --headers -1 --trim-spaces --encrypt-connection strict --input-file %s` |

Custom commands: pass any string with `%s` as the file placeholder.

## Configuration

Stored in the initial migration file as comments:

```sql
-- sql_command: psql "$PG_URL" -v ON_ERROR_STOP=on --no-align --tuples-only --file %s
-- migrations_log: ../migrations.log
```

These are read by the CLI on every run. Edit them to change the sql command or log path.
