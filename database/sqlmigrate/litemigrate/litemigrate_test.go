package litemigrate_test

import (
	"database/sql"
	"errors"
	"testing"
	"testing/fstest"

	_ "modernc.org/sqlite"

	"github.com/therootcompany/golib/database/sqlmigrate"
	"github.com/therootcompany/golib/database/sqlmigrate/litemigrate"
)

// openMem opens a fresh in-memory SQLite database and returns the conn.
// The cleanup closes both the conn and the underlying *sql.DB.
func openMem(t *testing.T) *sql.Conn {
	t.Helper()
	return openMemDSN(t, ":memory:")
}

// openMemDSN opens an in-memory SQLite with the given DSN (for pragmas).
func openMemDSN(t *testing.T, dsn string) *sql.Conn {
	t.Helper()
	db, err := sql.Open("sqlite", dsn)
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

// TestAppliedOrdering verifies Applied sorts by name (ascending), regardless
// of insertion order. Guards against the ORDER BY clause being removed or
// the underlying query returning rows in arbitrary order.
func TestAppliedOrdering(t *testing.T) {
	conn := openMem(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE _migrations (id TEXT, name TEXT);
		INSERT INTO _migrations (id, name) VALUES ('ccc33333', '003_posts');
		INSERT INTO _migrations (id, name) VALUES ('aaa11111', '001_init');
		INSERT INTO _migrations (id, name) VALUES ('bbb22222', '002_users');
	`); err != nil {
		t.Fatalf("setup: %v", err)
	}

	m := litemigrate.New(conn)
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
	conn := openMem(t)
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

	m := litemigrate.New(conn)

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

	// Verify the domain tables actually exist
	for _, tbl := range []string{"test_widgets", "test_gadgets"} {
		if _, err := conn.ExecContext(ctx, "SELECT COUNT(*) FROM "+tbl); err != nil {
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
	conn := openMem(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE test_rollback (n INTEGER)`); err != nil {
		t.Fatalf("create: %v", err)
	}

	m := litemigrate.New(conn)
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
	if err := conn.QueryRowContext(ctx, "SELECT COUNT(*) FROM test_rollback").Scan(&count); err != nil {
		t.Fatalf("count: %v", err)
	}
	if count != 0 {
		t.Errorf("test_rollback count = %d, want 0 (rows should have been rolled back)", count)
	}
}

// TestForeignKeyEnforcement verifies that SQLite foreign key constraints
// are enforced when _pragma=foreign_keys(1) is in the DSN. Without the
// pragma, SQLite silently allows FK violations.
func TestForeignKeyEnforcement(t *testing.T) {
	conn := openMemDSN(t, ":memory:?_pragma=foreign_keys(1)")
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `
		CREATE TABLE test_parent (id INTEGER PRIMARY KEY);
		CREATE TABLE test_child (
			id INTEGER PRIMARY KEY,
			parent_id INTEGER,
			FOREIGN KEY (parent_id) REFERENCES test_parent(id)
		);
	`); err != nil {
		t.Fatalf("schema: %v", err)
	}

	m := litemigrate.New(conn)
	err := m.ExecUp(ctx, sqlmigrate.Migration{Name: "fk"}, `
		INSERT INTO test_child (id, parent_id) VALUES (1, 999);
	`)
	if err == nil {
		t.Fatal("ExecUp() = nil, want FK violation error")
	}
	if !errors.Is(err, sqlmigrate.ErrExecFailed) {
		t.Errorf("err = %v, want ErrExecFailed", err)
	}
}
