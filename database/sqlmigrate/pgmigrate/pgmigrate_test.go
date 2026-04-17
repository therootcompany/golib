package pgmigrate_test

import (
	"context"
	"errors"
	"os"
	"testing"
	"testing/fstest"

	"github.com/jackc/pgx/v5"

	"github.com/therootcompany/golib/database/sqlmigrate"
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
	t.Cleanup(func() { _ = conn.Close(context.Background()) })

	// Use a per-test schema so concurrent tests don't collide and
	// _migrations is guaranteed not to exist on entry.
	schema := "pgmigrate_test_" + sanitize(t.Name())
	if _, err := conn.Exec(ctx, "DROP SCHEMA IF EXISTS "+schema+" CASCADE"); err != nil {
		t.Fatalf("drop schema: %v", err)
	}
	if _, err := conn.Exec(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	// Cleanup uses a fresh context because t.Context() is canceled
	// before cleanup runs, which would silently fail the DROP SCHEMA.
	t.Cleanup(func() {
		_, _ = conn.Exec(context.Background(), "DROP SCHEMA IF EXISTS "+schema+" CASCADE")
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

// TestAppliedOrdering verifies Applied sorts by name (ascending), regardless
// of insertion order. Guards against the ORDER BY clause being removed or
// the underlying query returning rows in arbitrary order.
func TestAppliedOrdering(t *testing.T) {
	conn := connect(t)
	ctx := t.Context()

	if _, err := conn.Exec(ctx, `
		CREATE TABLE _migrations (id TEXT, name TEXT);
		INSERT INTO _migrations (id, name) VALUES ('ccc33333', '003_posts');
		INSERT INTO _migrations (id, name) VALUES ('aaa11111', '001_init');
		INSERT INTO _migrations (id, name) VALUES ('bbb22222', '002_users');
	`); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m := pgmigrate.New(conn)
	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied() error = %v", err)
	}
	wantNames := []string{"001_init", "002_users", "003_posts"}
	if len(applied) != len(wantNames) {
		t.Fatalf("Applied() len = %d, want %d", len(applied), len(wantNames))
	}
	for i, w := range wantNames {
		if applied[i].Name != w {
			t.Errorf("applied[%d].Name = %q, want %q", i, applied[i].Name, w)
		}
	}
}

// TestEndToEndCycle runs a real Collect → Up → Applied → Down → Applied
// cycle through the sqlmigrate orchestrator. Catches wiring bugs between
// Migrator and the orchestrator that the in-package mockMigrator tests
// cannot.
func TestEndToEndCycle(t *testing.T) {
	conn := connect(t)
	ctx := t.Context()

	fsys := fstest.MapFS{
		"001_init.up.sql": {Data: []byte(`
			CREATE TABLE _migrations (id TEXT, name TEXT);
			CREATE TABLE test_widgets (n INTEGER);
			INSERT INTO _migrations (name, id) VALUES ('001_init', 'aaaa1111');
		`)},
		"001_init.down.sql": {Data: []byte(`
			DROP TABLE test_widgets;
			DROP TABLE _migrations;
		`)},
		"002_gadgets.up.sql": {Data: []byte(`
			CREATE TABLE test_gadgets (n INTEGER);
			INSERT INTO _migrations (name, id) VALUES ('002_gadgets', 'bbbb2222');
		`)},
		"002_gadgets.down.sql": {Data: []byte(`
			DROP TABLE test_gadgets;
			DELETE FROM _migrations WHERE id = 'bbbb2222';
		`)},
	}
	ddls, err := sqlmigrate.Collect(fsys, ".")
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}

	m := pgmigrate.New(conn)

	ran, err := sqlmigrate.Up(ctx, m, ddls, -1)
	if err != nil {
		t.Fatalf("Up: %v", err)
	}
	if len(ran) != 2 {
		t.Fatalf("ran = %d, want 2", len(ran))
	}

	applied, err := m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied: %v", err)
	}
	if len(applied) != 2 {
		t.Fatalf("applied = %d, want 2", len(applied))
	}
	if applied[0].ID != "aaaa1111" || applied[1].ID != "bbbb2222" {
		t.Errorf("applied IDs = %+v, want [aaaa1111 bbbb2222]", applied)
	}

	for _, tbl := range []string{"test_widgets", "test_gadgets"} {
		if _, err := conn.Exec(ctx, "SELECT COUNT(*) FROM "+tbl); err != nil {
			t.Errorf("expected table %q to exist: %v", tbl, err)
		}
	}

	rolled, err := sqlmigrate.Down(ctx, m, ddls, -1)
	if err != nil {
		t.Fatalf("Down: %v", err)
	}
	if len(rolled) != 2 {
		t.Fatalf("rolled = %d, want 2", len(rolled))
	}

	applied, err = m.Applied(ctx)
	if err != nil {
		t.Fatalf("Applied after Down: %v", err)
	}
	if len(applied) != 0 {
		t.Errorf("applied after Down = %d, want 0", len(applied))
	}
}

// TestDMLRollback verifies that when a migration contains multiple DML
// statements and one fails, earlier statements in the same migration are
// rolled back. Uses an INSERT into a nonexistent table as the failure
// trigger so the test is portable across backends.
func TestDMLRollback(t *testing.T) {
	conn := connect(t)
	ctx := t.Context()

	if _, err := conn.Exec(ctx, `CREATE TABLE test_rollback (n INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	m := pgmigrate.New(conn)
	err := m.ExecUp(ctx, sqlmigrate.Migration{Name: "rollback"}, `
		INSERT INTO test_rollback (n) VALUES (1);
		INSERT INTO test_rollback (n) VALUES (2);
		INSERT INTO nonexistent_table (n) VALUES (3);
	`)
	if err == nil {
		t.Fatal("ExecUp() = nil, want error")
	}
	if !errors.Is(err, sqlmigrate.ErrExecFailed) {
		t.Errorf("err = %v, want ErrExecFailed", err)
	}

	var count int
	if err := conn.QueryRow(ctx, "SELECT COUNT(*) FROM test_rollback").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("test_rollback count = %d, want 0 (rows should have been rolled back)", count)
	}
}
