// Package mymigrate implements sqlmigrate.Migrator for MySQL and MariaDB
// using database/sql with github.com/go-sql-driver/mysql.
//
// The caller must open the *sql.DB with multiStatements=true in the DSN
// for multi-statement migration files to work:
//
//	db, err := sql.Open("mysql", "user:pass@tcp(host:3306)/dbname?multiStatements=true")
package mymigrate

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/go-sql-driver/mysql"

	"github.com/therootcompany/golib/database/sqlmigrate"
)

// Migrator implements sqlmigrate.Migrator using a *sql.DB with MySQL/MariaDB.
type Migrator struct {
	DB *sql.DB
}

// New creates a Migrator from the given database handle.
func New(db *sql.DB) *Migrator {
	return &Migrator{DB: db}
}

var _ sqlmigrate.Migrator = (*Migrator)(nil)

// ExecUp runs the up migration SQL inside a transaction.
func (m *Migrator) ExecUp(ctx context.Context, mig sqlmigrate.Migration) error {
	return m.execInTx(ctx, mig.Up)
}

// ExecDown runs the down migration SQL inside a transaction.
func (m *Migrator) ExecDown(ctx context.Context, mig sqlmigrate.Migration) error {
	return m.execInTx(ctx, mig.Down)
}

func (m *Migrator) execInTx(ctx context.Context, sqlStr string) error {
	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin: %w", sqlmigrate.ErrExecFailed, err)
	}
	defer tx.Rollback() //nolint:errcheck

	if _, err := tx.ExecContext(ctx, sqlStr); err != nil {
		return fmt.Errorf("%w: exec: %w", sqlmigrate.ErrExecFailed, err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("%w: commit: %w", sqlmigrate.ErrExecFailed, err)
	}

	return nil
}

// Applied returns all applied migrations from the _migrations table.
// Returns an empty slice if the table does not exist (MySQL error 1146).
func (m *Migrator) Applied(ctx context.Context) ([]sqlmigrate.AppliedMigration, error) {
	rows, err := m.DB.QueryContext(ctx, "SELECT id, name FROM _migrations ORDER BY name")
	if err != nil {
		if mysqlErr, ok := errors.AsType[*mysql.MySQLError](err); ok && mysqlErr.Number == 1146 {
			return nil, nil
		}
		return nil, fmt.Errorf("%w: %w", sqlmigrate.ErrQueryApplied, err)
	}
	defer rows.Close()

	var applied []sqlmigrate.AppliedMigration
	for rows.Next() {
		var a sqlmigrate.AppliedMigration
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
