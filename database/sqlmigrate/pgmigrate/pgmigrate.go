// Package pgmigrate implements sqlmigrate.Migrator for PostgreSQL via pgx/v5.
//
// # Multi-tenant schemas
//
// Pass a Schema to target a specific PostgreSQL schema:
//
//	runner := pgmigrate.New(conn)
//	runner.Schema = "authz"
//
// Each schema gets its own _migrations table, so tenants are migrated
// independently. The sql-migrate CLI supports this via TENANT_SCHEMA;
// see the CLI help for details.
package pgmigrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/therootcompany/golib/database/sqlmigrate"
)

// Migrator implements sqlmigrate.Migrator using a single pgx.Conn.
type Migrator struct {
	Conn   *pgx.Conn
	Schema string // optional; qualifies the _migrations table (e.g. "authz")
}

// New creates a Migrator from the given connection.
func New(conn *pgx.Conn) *Migrator {
	return &Migrator{Conn: conn}
}

// migrationsTable returns the (optionally schema-qualified) _migrations table
// name, safe for direct interpolation into a query string.
func (r *Migrator) migrationsTable() string {
	if r.Schema == "" {
		return "_migrations"
	}
	return pgx.Identifier{r.Schema, "_migrations"}.Sanitize()
}

// verify interface compliance at compile time
var _ sqlmigrate.Migrator = (*Migrator)(nil)

// ExecUp runs the up migration SQL inside a PostgreSQL transaction.
func (r *Migrator) ExecUp(ctx context.Context, m sqlmigrate.Migration, sql string) error {
	return r.execInTx(ctx, sql)
}

// ExecDown runs the down migration SQL inside a PostgreSQL transaction.
func (r *Migrator) ExecDown(ctx context.Context, m sqlmigrate.Migration, sql string) error {
	return r.execInTx(ctx, sql)
}

func (r *Migrator) execInTx(ctx context.Context, sql string) error {
	tx, err := r.Conn.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: begin: %w", sqlmigrate.ErrExecFailed, err)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err := tx.Exec(ctx, sql); err != nil {
		return fmt.Errorf("%w: exec: %w", sqlmigrate.ErrExecFailed, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: commit: %w", sqlmigrate.ErrExecFailed, err)
	}

	return nil
}

// Applied returns all applied migrations from the _migrations table.
// Returns an empty slice if the table does not exist (PG error 42P01).
//
// Note: pgx.Conn.Query is lazy — when the table is missing, the 42P01
// error may surface at rows.Err() rather than at Query(). Both sites
// must check for it.
func (r *Migrator) Applied(ctx context.Context) ([]sqlmigrate.Migration, error) {
	rows, err := r.Conn.Query(ctx, "SELECT id, name FROM "+r.migrationsTable()+" ORDER BY name")
	if err != nil {
		if isUndefinedTable(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", sqlmigrate.ErrQueryApplied, err)
	}
	defer rows.Close()

	var applied []sqlmigrate.Migration
	for rows.Next() {
		var a sqlmigrate.Migration
		if err := rows.Scan(&a.ID, &a.Name); err != nil {
			return nil, fmt.Errorf("%w: scanning row: %w", sqlmigrate.ErrQueryApplied, err)
		}
		applied = append(applied, a)
	}
	if err := rows.Err(); err != nil {
		if isUndefinedTable(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: reading rows: %w", sqlmigrate.ErrQueryApplied, err)
	}

	return applied, nil
}

// isUndefinedTable reports whether err is PostgreSQL error 42P01
// (undefined_table), which is what we get when _migrations doesn't exist yet.
func isUndefinedTable(err error) bool {
	pgErr, ok := errors.AsType[*pgconn.PgError](err)
	return ok && pgErr.Code == "42P01"
}
