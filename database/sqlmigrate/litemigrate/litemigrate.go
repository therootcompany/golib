// Package litemigrate implements sqlmigrate.Migrator for SQLite
// using database/sql. The caller imports the driver:
//
//	import _ "modernc.org/sqlite"
//
//	db, err := sql.Open("sqlite", "app.db?_pragma=foreign_keys(1)")
//	conn, err := db.Conn(ctx)
//
// SQLite disables foreign key enforcement by default. The _pragma DSN
// parameter enables it on every connection the pool opens.
package litemigrate

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/therootcompany/golib/database/sqlmigrate"
)

// Migrator implements sqlmigrate.Migrator using a *sql.Conn with SQLite.
type Migrator struct {
	Conn *sql.Conn
}

// New creates a Migrator from the given connection.
// Use db.Conn(ctx) to obtain a *sql.Conn from a *sql.DB.
func New(conn *sql.Conn) *Migrator {
	return &Migrator{Conn: conn}
}

var _ sqlmigrate.Migrator = (*Migrator)(nil)

// ExecUp runs the up migration SQL inside a transaction.
func (m *Migrator) ExecUp(ctx context.Context, mig sqlmigrate.Migration, sql string) error {
	return m.execInTx(ctx, sql)
}

// ExecDown runs the down migration SQL inside a transaction.
func (m *Migrator) ExecDown(ctx context.Context, mig sqlmigrate.Migration, sql string) error {
	return m.execInTx(ctx, sql)
}

func (m *Migrator) execInTx(ctx context.Context, sqlStr string) error {
	tx, err := m.Conn.BeginTx(ctx, nil)
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
// Returns an empty slice if the table does not exist.
func (m *Migrator) Applied(ctx context.Context) ([]sqlmigrate.Migration, error) {
	rows, err := m.Conn.QueryContext(ctx, "SELECT id, name FROM _migrations ORDER BY name")
	if err != nil {
		// SQLite reports "no such table: _migrations" — stable across versions
		if strings.Contains(err.Error(), "no such table: _migrations") {
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
