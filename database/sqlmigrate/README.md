# sqlmigrate

Database-agnostic SQL migration library for Go.

[![Go Reference](https://pkg.go.dev/badge/github.com/therootcompany/golib/database/sqlmigrate.svg)](https://pkg.go.dev/github.com/therootcompany/golib/database/sqlmigrate)

## Backend packages

Each backend is a separate Go module to avoid pulling unnecessary drivers:

| Package | Database | Driver |
|---------|----------|--------|
| [pgmigrate](https://pkg.go.dev/github.com/therootcompany/golib/database/sqlmigrate/pgmigrate) | PostgreSQL | pgx/v5 |
| [mymigrate](https://pkg.go.dev/github.com/therootcompany/golib/database/sqlmigrate/mymigrate) | MySQL / MariaDB | go-sql-driver/mysql |
| [litemigrate](https://pkg.go.dev/github.com/therootcompany/golib/database/sqlmigrate/litemigrate) | SQLite | database/sql (caller imports driver) |
| [msmigrate](https://pkg.go.dev/github.com/therootcompany/golib/database/sqlmigrate/msmigrate) | SQL Server | go-mssqldb |
| [shmigrate](https://pkg.go.dev/github.com/therootcompany/golib/database/sqlmigrate/shmigrate) | Shell scripts | (uses native CLI) |

## CLI

The [sql-migrate](https://pkg.go.dev/github.com/therootcompany/golib/cmd/sql-migrate/v2) CLI
uses _shmigrate_ to generate shell scripts for managing migrations without a Go dependency at runtime.
