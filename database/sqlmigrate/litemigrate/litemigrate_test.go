package litemigrate_test

import (
	"database/sql"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/therootcompany/golib/database/sqlmigrate/litemigrate"
)

// openMem opens a fresh in-memory SQLite database and returns the conn.
// The cleanup closes both the conn and the underlying *sql.DB.
func openMem(t *testing.T) *sql.Conn {
	t.Helper()
	db, err := sql.Open("sqlite", ":memory:")
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	conn, err := db.Conn(t.Context())
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	return conn
}

// TestAppliedNoMigrationsTable verifies Applied returns (nil, nil) when
// the _migrations table does not exist. Regression test for the
// table-missing handling — caught a class of bugs where the error type
// or message changes between SQLite driver versions.
func TestAppliedNoMigrationsTable(t *testing.T) {
	conn := openMem(t)

	m := litemigrate.New(conn)
	applied, err := m.Applied(t.Context())
	if err != nil {
		t.Fatalf("Applied() error = %v, want nil", err)
	}
	if len(applied) != 0 {
		t.Errorf("Applied() len = %d, want 0", len(applied))
	}
}

// TestAppliedWithMigrationsTable verifies Applied reads existing rows.
func TestAppliedWithMigrationsTable(t *testing.T) {
	conn := openMem(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE _migrations (id TEXT, name TEXT);
		INSERT INTO _migrations (id, name) VALUES ('abc12345', '0001_init');
		INSERT INTO _migrations (id, name) VALUES ('def67890', '0002_users');
	`); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m := litemigrate.New(conn)
	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() error = %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("Applied() len = %d, want 2", len(applied))
	}
	if applied[0].Name != "0001_init" || applied[0].ID != "abc12345" {
		t.Errorf("applied[0] = %+v, want {abc12345 0001_init}", applied[0])
	}
	if applied[1].Name != "0002_users" || applied[1].ID != "def67890" {
		t.Errorf("applied[1] = %+v, want {def67890 0002_users}", applied[1])
	}
}

// TestAppliedEmptyMigrationsTable verifies Applied returns an empty slice
// (not an error) when _migrations exists but has no rows.
func TestAppliedEmptyMigrationsTable(t *testing.T) {
	conn := openMem(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE _migrations (id TEXT, name TEXT)`); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m := litemigrate.New(conn)
	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() error = %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("Applied() len = %d, want 0", len(applied))
	}
}

// TestAppliedAfterDropTable verifies Applied still returns (nil, nil) after
// the _migrations table is dropped — exercises any prepared-statement
// caching the driver may do.
func TestAppliedAfterDropTable(t *testing.T) {
	conn := openMem(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE _migrations (id TEXT, name TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	m := litemigrate.New(conn)
	if _, err := m.Applied(ctx); err != nil {
		t.Fatalf("first Applied: %v", err)
	}

	if _, err := conn.ExecContext(ctx, `DROP TABLE _migrations`); err != nil {
		t.Fatalf("drop: %v", err)
	}

	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() after DROP TABLE error = %v, want nil", err)
	}
	if len(applied) != 0 {
		t.Errorf("Applied() len = %d, want 0", len(applied))
	}
}
