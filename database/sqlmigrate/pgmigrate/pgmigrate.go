// Package pgmigrate implements sqlmigrate.Migrator for PostgreSQL via pgx/v5.
//
// # Multi-tenant schemas
//
// For schema-based multi-tenancy, set search_path on the pool's connection
// config so all migrations target the correct schema:
//
//	import "github.com/jackc/pgx/v5"
//
//	config, _ := pgxpool.ParseConfig(pgURL)
//	config.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
//	    _, err := conn.Exec(ctx, fmt.Sprintf("SET search_path TO %s", pgx.Identifier{schema}.Sanitize()))
//	    return err
//	}
//	pool, _ := pgxpool.NewWithConfig(ctx, config)
//	runner := pgmigrate.New(pool)
//
// Each schema gets its own _migrations table, so tenants are migrated
// independently. The sql-migrate CLI supports this via TENANT_SCHEMA;
// see the CLI help for details.
package pgmigrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/therootcompany/golib/database/sqlmigrate"
)

// Migrator implements sqlmigrate.Migrator using a pgxpool.Pool.
type Migrator struct {
	Pool *pgxpool.Pool
}

// New creates a Migrator from the given pool.
func New(pool *pgxpool.Pool) *Migrator {
	return &Migrator{Pool: pool}
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
	tx, err := r.Pool.Begin(ctx)
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
func (r *Migrator) Applied(ctx context.Context) ([]sqlmigrate.Migration, error) {
	rows, err := r.Pool.Query(ctx, "SELECT id, name FROM _migrations ORDER BY name")
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "42P01" {
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
		return nil, fmt.Errorf("%w: reading rows: %w", sqlmigrate.ErrQueryApplied, err)
	}

	return applied, nil
}
