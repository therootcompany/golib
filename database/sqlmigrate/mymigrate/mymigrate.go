// Package mymigrate implements sqlmigrate.Migrator for MySQL and MariaDB
// using database/sql with github.com/go-sql-driver/mysql.
//
// The *sql.DB must be opened with multiStatements=true in the DSN;
// without it, multi-statement migration files will fail. New returns
// an error if multi-statement support is not detected:
//
//	db, err := sql.Open("mysql", "user:pass@tcp(host:3306)/dbname?multiStatements=true")
//
// MySQL and MariaDB do not support transactional DDL. Statements like
// CREATE TABLE and ALTER TABLE cause an implicit commit, so if a migration
// fails partway through, earlier DDL statements in that migration will
// already be committed. DML-only migrations are fully transactional.
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
// Returns an error if the connection does not support multi-statement
// queries (multiStatements=true must be set in the DSN).
func New(db *sql.DB) (*Migrator, error) {
	// Probe for multi-statement support. Without it, migration files
	// that contain more than one statement silently execute only the first.
	if _, err := db.Exec("DO 1; DO 1"); err != nil {
		return nil, fmt.Errorf("mymigrate: connection requires multiStatements=true in DSN: %w", err)
	}
	return &Migrator{DB: db}, nil
}

var _ sqlmigrate.Migrator = (*Migrator)(nil)

// ExecUp runs the up migration SQL in a transaction. DDL statements
// (CREATE, ALTER, DROP) are implicitly committed by MySQL; see package docs.
func (m *Migrator) ExecUp(ctx context.Context, mig sqlmigrate.Migration) error {
	return m.exec(ctx, mig.Up)
}

// ExecDown runs the down migration SQL in a transaction. DDL statements
// (CREATE, ALTER, DROP) are implicitly committed by MySQL; see package docs.
func (m *Migrator) ExecDown(ctx context.Context, mig sqlmigrate.Migration) error {
	return m.exec(ctx, mig.Down)
}

func (m *Migrator) exec(ctx context.Context, sqlStr string) error {
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
