---
name: use-sql-migrate-sqlite
description: SQLite migrations with sql-migrate and litemigrate. Use when setting up SQLite migrations, configuring foreign keys, or using modernc.org/sqlite driver.
depends: [use-sqlmigrate]
---

## CLI setup

```sh
sql-migrate -d ./sql/migrations/ init --sql-command sqlite
```

## Environment

```sh
# .env
SQLITE_PATH='./app.db'
```

## Go library

```go
import (
    "database/sql"

    _ "modernc.org/sqlite"
    "github.com/therootcompany/golib/database/sqlmigrate"
    "github.com/therootcompany/golib/database/sqlmigrate/litemigrate"
)

// MUST: enable foreign keys via pragma
db, err := sql.Open("sqlite", dbPath+"?_pragma=foreign_keys(1)")
conn, err := db.Conn(ctx)
defer func() { _ = conn.Close() }()

runner := litemigrate.New(conn)
applied, err := sqlmigrate.Latest(ctx, runner, scripts)
```

MUST: The caller imports the SQLite driver (`modernc.org/sqlite` recommended — pure Go, no CGo).

## SQL dialect notes

- `datetime('now')` instead of `CURRENT_TIMESTAMP` for default values in expressions
- `TEXT` for timestamp columns (SQLite has no native datetime type)
- `INSERT OR IGNORE` for idempotent seeds (not `INSERT IGNORE`)
- String concatenation: `id || CHAR(9) || name` (used by sync query)
- `ALTER TABLE ... DROP COLUMN` requires SQLite 3.35.0+ (2021-03-12)
- "no such table" error string used to detect missing `_migrations` table
- Default path: `todos.db` if no env var set

## sqlc with SQLite

SQLite `CHAR(n)` columns map to `interface{}` in sqlc. Use column-level overrides:

```yaml
# sqlc.yaml
sql:
  - schema: "sql/migrations/"
    queries: "sql/queries/"
    engine: "sqlite"
    gen:
      go:
        out: "internal/tododb"
        overrides:
          - column: "todos.id"
            go_type: "string"
          - column: "todos.status"
            go_type: "string"
```
