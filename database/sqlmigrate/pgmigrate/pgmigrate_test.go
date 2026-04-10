package pgmigrate_test

import (
	"os"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/therootcompany/golib/database/sqlmigrate/pgmigrate"
)

// connect opens a pgx connection from PG_TEST_URL, skips the test if
// the env var is unset, and isolates the test in its own schema with
// automatic cleanup.
func connect(t *testing.T) *pgx.Conn {
	t.Helper()
	pgURL := os.Getenv("PG_TEST_URL")
	if pgURL == "" {
		t.Skip("PG_TEST_URL not set")
	}

	ctx := t.Context()
	conn, err := pgx.Connect(ctx, pgURL)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close(ctx) })

	// Use a per-test schema so concurrent tests don't collide and
	// _migrations is guaranteed not to exist on entry.
	schema := "pgmigrate_test_" + sanitize(t.Name())
	if _, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() {
		_, _ = conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
	})
	if _, err := conn.Exec(ctx, "SET search_path TO "+schema); err != nil {
		t.Fatalf("set search_path: %v", err)
	}

	return conn
}

// sanitize converts a test name to a valid PostgreSQL identifier suffix.
func sanitize(s string) string {
	out := make([]byte, 0, len(s))
	for _, c := range []byte(s) {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
			out = append(out, c)
		default:
			out = append(out, '_')
		}
	}
	return string(out)
}

// TestAppliedNoMigrationsTable is the regression test for the bug where
// pgx surfaces error 42P01 lazily at rows.Err() rather than at Query().
// Before the fix, this returned: reading rows: ERROR: relation
// "_migrations" does not exist (SQLSTATE 42P01).
func TestAppliedNoMigrationsTable(t *testing.T) {
	conn := connect(t)

	m := pgmigrate.New(conn)
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

	if _, err := conn.Exec(ctx, `
		CREATE TABLE _migrations (id TEXT, name TEXT);
		INSERT INTO _migrations (id, name) VALUES ('abc12345', '0001_init');
		INSERT INTO _migrations (id, name) VALUES ('def67890', '0002_users');
	`); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m := pgmigrate.New(conn)
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

// TestAppliedEmptyMigrationsTable verifies Applied returns an empty
// slice (not an error) when _migrations exists but has no rows.
func TestAppliedEmptyMigrationsTable(t *testing.T) {
	conn := connect(t)
	ctx := t.Context()

	if _, err := conn.Exec(ctx, `CREATE TABLE _migrations (id TEXT, name TEXT)`); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m := pgmigrate.New(conn)
	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() error = %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("Applied() len = %d, want 0", len(applied))
	}
}

// TestAppliedAfterDropTable verifies Applied handles the case where the
// _migrations table once existed (so pgx may have cached its prepared
// statement) but has been dropped. This is the scenario most likely to
// trigger pgx's lazy 42P01 error at rows.Err() rather than at Query().
func TestAppliedAfterDropTable(t *testing.T) {
	conn := connect(t)
	ctx := t.Context()

	if _, err := conn.Exec(ctx, `CREATE TABLE _migrations (id TEXT, name TEXT)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	m := pgmigrate.New(conn)
	// Prime pgx's prepared-statement cache by calling Applied successfully.
	if _, err := m.Applied(ctx); err != nil {
		t.Fatalf("first Applied: %v", err)
	}

	// Now drop the table out from under pgx. The cached prepared statement
	// references a relation that no longer exists; the next Applied call
	// must still return (nil, nil), not an error.
	if _, err := conn.Exec(ctx, `DROP TABLE _migrations`); err != nil {
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
