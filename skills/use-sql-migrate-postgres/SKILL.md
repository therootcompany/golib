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

```go
import (
    "github.com/jackc/pgx/v5"
    "github.com/therootcompany/golib/database/sqlmigrate"
    "github.com/therootcompany/golib/database/sqlmigrate/pgmigrate"
)

// MUST: use pgx.Connect (single conn), not pgxpool.New
conn, err := pgx.Connect(ctx, pgURL)
defer func() { _ = conn.Close(ctx) }()

runner := pgmigrate.New(conn)
applied, err := sqlmigrate.Latest(ctx, runner, scripts)
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
- Error code 42P01 = table doesn't exist (handled automatically by pgmigrate)
