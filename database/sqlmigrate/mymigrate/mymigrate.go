// Package mymigrate implements sqlmigrate.Migrator for MySQL and MariaDB
// using database/sql with github.com/go-sql-driver/mysql.
//
// The *sql.DB must be opened with multiStatements=true in the DSN;
// without it, multi-statement migration files will silently execute only
// the first statement. The multiStatements requirement is validated lazily
// on the first ExecUp or ExecDown call:
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
	DB        *sql.DB
	validated bool
}

// New creates a Migrator from the given database handle.
// The multiStatements=true DSN requirement is validated lazily on the
// first ExecUp or ExecDown call.
func New(db *sql.DB) *Migrator {
	return &Migrator{DB: db}
}

var _ sqlmigrate.Migrator = (*Migrator)(nil)

// ExecUp runs the up migration SQL in a transaction. DDL statements
// (CREATE, ALTER, DROP) are implicitly committed by MySQL; see package docs.
func (m *Migrator) ExecUp(ctx context.Context, mig sqlmigrate.Migration, sql string) error {
	return m.exec(ctx, sql)
}

// ExecDown runs the down migration SQL in a transaction. DDL statements
// (CREATE, ALTER, DROP) are implicitly committed by MySQL; see package docs.
func (m *Migrator) ExecDown(ctx context.Context, mig sqlmigrate.Migration, sql string) error {
	return m.exec(ctx, sql)
}

func (m *Migrator) exec(ctx context.Context, sqlStr string) error {
	if !m.validated {
		// Probe for multi-statement support. Without it, migration files
		// that contain more than one statement silently execute only the first.
		if _, err := m.DB.ExecContext(ctx, "DO 1; DO 1"); err != nil {
			return fmt.Errorf(
				"%w: mymigrate: migration requires multiStatements=true in the MySQL DSN",
				sqlmigrate.ErrExecFailed,
			)
		}
		m.validated = true
	}

	tx, err := m.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("%w: begin: %w", sqlmigrate.ErrExecFailed, err)
	}
	defer func() { _ = tx.Rollback() }()

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
func (m *Migrator) Applied(ctx context.Context) ([]sqlmigrate.Migration, error) {
	rows, err := m.DB.QueryContext(ctx, "SELECT id, name FROM _migrations ORDER BY name")
	if err != nil {
		if mysqlErr, ok := errors.AsType[*mysql.MySQLError](err); ok && mysqlErr.Number == 1146 {
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
