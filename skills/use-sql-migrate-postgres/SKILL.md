---
name: use-sql-migrate-postgres
description: PostgreSQL migrations with sql-migrate and pgmigrate. Use when setting up PostgreSQL migrations, schema multi-tenancy, or pgx connection for migrations.
depends: [use-sqlmigrate]
---

## CLI setup

```sh
sql-migrate -d ./sql/migrations/ init --sql-command psql
```

## Environment

```sh
# .env
PG_URL='postgres://user:pass@localhost:5432/mydb?sslmode=disable'
```

## Go library

Use `sqlmigrate.Collect(fsys, subpath)` first to parse the embedded files.

**`//go:embed` constraint:** embed cannot traverse `..`, so the embed directive must live in a package that is at or above the `sql/migrations/` directory. Pass `fs.FS` down to migration helpers rather than embedding inside them.

```go
import (
    "embed"
    "io/fs"

    "github.com/jackc/pgx/v5"
    "github.com/therootcompany/golib/database/sqlmigrate"
    "github.com/therootcompany/golib/database/sqlmigrate/pgmigrate"
)

//go:embed sql/migrations
var migrationsFS embed.FS

func runMigrations(ctx context.Context, pgURL string) error {
    scripts, err := sqlmigrate.Collect(migrationsFS, "sql/migrations")
    if err != nil {
        return err
    }

    // MUST: use pgx.Connect (single conn), not pgxpool.New
    conn, err := pgx.Connect(ctx, pgURL)
    if err != nil {
        return err
    }
    defer func() { _ = conn.Close(ctx) }()

    runner := pgmigrate.New(conn)
    _, err = sqlmigrate.Latest(ctx, runner, scripts)
    return err
}
```

### Key types

```go
// sqlmigrate.Script — one migration pair (up + down SQL + name + ID)
// sqlmigrate.Migration — name + ID only (returned by Applied, Latest, etc.)
// sqlmigrate.Status — Applied []Migration + Pending []Migration

scripts, err := sqlmigrate.Collect(fsys, subpath)  // parse fs.FS → []Script
applied, err := sqlmigrate.Latest(ctx, r, scripts)  // apply all pending → []Migration
applied, err := sqlmigrate.Up(ctx, r, scripts, n)   // apply n migrations
rolled,  err := sqlmigrate.Down(ctx, r, scripts, n) // roll back n migrations
status,  err := sqlmigrate.GetStatus(ctx, r, scripts)
```

## Schema multi-tenancy

Each PostgreSQL schema gets its own `_migrations` table. Tenants are migrated independently.

### CLI

```sh
PGOPTIONS="-c search_path=tenant123" sql-migrate -d ./sql/migrations/ up | sh
```

### Go library

```go
conn, err := pgx.Connect(ctx, pgURL)
_, err = conn.Exec(ctx, fmt.Sprintf(
    "SET search_path TO %s",
    pgx.Identifier{schema}.Sanitize(),
))
runner := pgmigrate.New(conn)
```

## SQL dialect notes

- `CREATE TABLE IF NOT EXISTS` works
- `ON CONFLICT DO NOTHING` for idempotent seeds
- String concatenation: `id || CHR(9) || name` (used by sync query)
- Timestamps: `TIMESTAMP DEFAULT CURRENT_TIMESTAMP`
- Error code 42P01 = table doesn't exist (handled automatically by pgmigrate for initial migration)
