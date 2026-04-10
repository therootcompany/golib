package msmigrate_test

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/microsoft/go-mssqldb"

	"github.com/therootcompany/golib/database/sqlmigrate/msmigrate"
)

// connect opens a *sql.Conn from MSSQL_TEST_URL, skips the test if the
// env var is unset, and ensures _migrations does not exist on entry,
// with cleanup on exit.
//
// Note: SQL Server does not have per-connection search_path. Tests run
// against the user's default schema and clean up _migrations directly,
// rather than using a per-test schema.
func connect(t *testing.T) *sql.Conn {
	t.Helper()
	url := os.Getenv("MSSQL_TEST_URL")
	if url == "" {
		t.Skip("MSSQL_TEST_URL not set")
	}

	ctx := t.Context()
	db, err := sql.Open("sqlserver", url)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.ExecContext(ctx, "DROP TABLE IF EXISTS _migrations"); err != nil {
		t.Fatalf("pre-cleanup _migrations: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(ctx, "DROP TABLE IF EXISTS _migrations")
	})

	return conn
}

// TestAppliedNoMigrationsTable verifies Applied returns (nil, nil) when
// the _migrations table does not exist (SQL Server error 208). Defensive
// regression test against drivers that may surface the error lazily.
func TestAppliedNoMigrationsTable(t *testing.T) {
	conn := connect(t)

	m := msmigrate.New(conn)
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
	conn := connect(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE _migrations (id NVARCHAR(16), name NVARCHAR(255))
	`); err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO _migrations (id, name) VALUES ('abc12345', '0001_init'), ('def67890', '0002_users')`,
	); err != nil {
		t.Fatalf("insert: %v", err)
	}

	m := msmigrate.New(conn)
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
	conn := connect(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE _migrations (id NVARCHAR(16), name NVARCHAR(255))`); err != nil {
		t.Fatalf("create: %v", err)
	}

	m := msmigrate.New(conn)
	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() error = %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("Applied() len = %d, want 0", len(applied))
	}
}

// TestAppliedAfterDropTable verifies Applied still returns (nil, nil)
// after the _migrations table is dropped — exercises any prepared-
// statement caching the driver may do.
func TestAppliedAfterDropTable(t *testing.T) {
	conn := connect(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE _migrations (id NVARCHAR(16), name NVARCHAR(255))`); err != nil {
		t.Fatalf("create: %v", err)
	}

	m := msmigrate.New(conn)
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
