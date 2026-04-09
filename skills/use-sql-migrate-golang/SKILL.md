---
name: use-sql-migrate-golang
description: Embed SQL migrations in Go applications using sqlmigrate library. Use when writing Go code that runs migrations on startup, implements auto-migrate, or uses the Migrator interface. Covers pgmigrate, mymigrate, litemigrate, msmigrate.
depends: [use-sqlmigrate, go-stack]
---

## Modules

Each backend is a separate Go module. Import only what you need:

| Module | Import path |
|--------|-------------|
| Core | `github.com/therootcompany/golib/database/sqlmigrate` |
| PostgreSQL | `github.com/therootcompany/golib/database/sqlmigrate/pgmigrate` |
| MySQL/MariaDB | `github.com/therootcompany/golib/database/sqlmigrate/mymigrate` |
| SQLite | `github.com/therootcompany/golib/database/sqlmigrate/litemigrate` |
| SQL Server | `github.com/therootcompany/golib/database/sqlmigrate/msmigrate` |

## Core API

```go
// Collect reads .up.sql/.down.sql pairs from an fs.FS
scripts, err := sqlmigrate.Collect(migrationsFS, "sql/migrations")

// Apply all pending migrations
applied, err := sqlmigrate.Latest(ctx, runner, scripts)

// Apply n pending migrations (-1 = all)
applied, err := sqlmigrate.Up(ctx, runner, scripts, n)

// Roll back n migrations (-1 = all, default pattern: 1)
rolled, err := sqlmigrate.Down(ctx, runner, scripts, n)

// Roll back all migrations
rolled, err := sqlmigrate.Drop(ctx, runner, scripts)

// Check status
status, err := sqlmigrate.GetStatus(ctx, runner, scripts)
// status.Applied, status.Pending
```

## Key types

```go
type Migration struct {
    ID   string // 8-char hex from INSERT statement
    Name string // e.g. "2026-04-05-001000_create-todos"
}

type Script struct {
    Migration
    Up   string // .up.sql content
    Down string // .down.sql content
}

type Migrator interface {
    ExecUp(ctx context.Context, m Migration, sql string) error
    ExecDown(ctx context.Context, m Migration, sql string) error
    Applied(ctx context.Context) ([]Migration, error)
}
```

## Embedding migrations

MUST: Use `embed.FS` to bundle migration files into the binary:

```go
//go:embed sql/migrations/*.sql
var migrationsFS embed.FS
```

## Backend setup pattern

MUST: Backends take a single connection, not a pool.

### database/sql backends (MySQL, SQLite, SQL Server)

```go
db, err := sql.Open("mysql", dsn)
// ...

// acquire a dedicated connection for migrations
conn, err := db.Conn(ctx)
// ...
defer func() { _ = conn.Close() }()

runner := mymigrate.New(conn) // or litemigrate.New(conn), msmigrate.New(conn)
```

### pgx backend (PostgreSQL)

```go
// single connection, not pool
conn, err := pgx.Connect(ctx, pgURL)
// ...
defer func() { _ = conn.Close(ctx) }()

runner := pgmigrate.New(conn)
```

## Auto-migrate on startup

Common pattern — run all pending migrations before serving:

```go
func main() {
    // ... open db, get conn ...

    scripts := mustCollectMigrations()
    runner := litemigrate.New(conn)

    // apply all pending (idempotent)
    if _, err := sqlmigrate.Latest(ctx, runner, scripts); err != nil {
        log.Fatalf("auto-migrate: %v", err)
    }

    // close migration conn, use db/pool for app queries
    _ = conn.Close()

    // ... start serving ...
}
```

## Example app structure

```
my-app/
  main.go              # flag parsing, DB setup, auto-migrate, dispatch
  demo.go              # app-specific CRUD (uses *sql.DB for queries)
  go.mod
  sql/
    migrations/
      0001-01-01-001000_init-migrations.up.sql
      0001-01-01-001000_init-migrations.down.sql
      2026-04-05-001000_create-todos.up.sql
      2026-04-05-001000_create-todos.down.sql
```

## Migrate subcommand pattern

Expose `migrate up/down/status/reset` as a subcommand:

```go
case "migrate":
    err = runMigrate(ctx, runner, migrations, subArgs)
case "add":
    autoMigrate(ctx, runner, migrations)
    err = runAdd(ctx, db, subArgs)
```

See example apps in `cmd/sql-migrate/examples/` for full implementations.
