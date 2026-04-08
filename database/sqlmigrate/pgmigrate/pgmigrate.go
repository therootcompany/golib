// Package pgmigrate implements sqlmigrate.Migrator for PostgreSQL via pgx/v5.
package pgmigrate

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
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
func (r *Migrator) ExecUp(ctx context.Context, m sqlmigrate.Migration) error {
	return r.execInTx(ctx, m.Up)
}

// ExecDown runs the down migration SQL inside a PostgreSQL transaction.
func (r *Migrator) ExecDown(ctx context.Context, m sqlmigrate.Migration) error {
	return r.execInTx(ctx, m.Down)
}

func (r *Migrator) execInTx(ctx context.Context, sql string) error {
	tx, err := r.Pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("%w: begin: %w", sqlmigrate.ErrExecFailed, err)
	}
	defer tx.Rollback(ctx) //nolint:errcheck

	if _, err := tx.Exec(ctx, sql); err != nil {
		return fmt.Errorf("%w: exec: %w", sqlmigrate.ErrExecFailed, err)
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("%w: commit: %w", sqlmigrate.ErrExecFailed, err)
	}

	return nil
}

// Applied returns the names of all applied migrations from the _migrations table.
// Returns an empty slice if the table does not exist (PG error 42P01).
func (r *Migrator) Applied(ctx context.Context) ([]string, error) {
	rows, err := r.Pool.Query(ctx, "SELECT name FROM _migrations ORDER BY name")
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "42P01" {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", sqlmigrate.ErrQueryApplied, err)
	}
	defer rows.Close()

	names, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("%w: reading rows: %w", sqlmigrate.ErrQueryApplied, err)
	}

	return names, nil
}
