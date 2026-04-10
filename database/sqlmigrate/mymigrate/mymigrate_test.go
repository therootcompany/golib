package mymigrate_test

import (
	"database/sql"
	"os"
	"testing"

	_ "github.com/go-sql-driver/mysql"

	"github.com/therootcompany/golib/database/sqlmigrate/mymigrate"
)

// connect opens a *sql.Conn from MYSQL_TEST_DSN, skips the test if the
// env var is unset, and isolates the test in its own database with
// automatic cleanup.
func connect(t *testing.T) *sql.Conn {
	t.Helper()
	dsn := os.Getenv("MYSQL_TEST_DSN")
	if dsn == "" {
		t.Skip("MYSQL_TEST_DSN not set")
	}

	ctx := t.Context()
	db, err := sql.Open("mysql", dsn)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	// Use a per-test database so concurrent tests don't collide and
	// _migrations is guaranteed not to exist on entry.
	dbName := "mymigrate_test_" + sanitize(t.Name())
	if _, err := db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+dbName); err != nil {
		t.Fatalf("drop database: %v", err)
	}
	if _, err := db.ExecContext(ctx, "CREATE DATABASE "+dbName); err != nil {
		t.Fatalf("create database: %v", err)
	}
	t.Cleanup(func() {
		_, _ = db.ExecContext(ctx, "DROP DATABASE IF EXISTS "+dbName)
	})

	conn, err := db.Conn(ctx)
	if err != nil {
		t.Fatalf("conn: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	if _, err := conn.ExecContext(ctx, "USE "+dbName); err != nil {
		t.Fatalf("use database: %v", err)
	}

	return conn
}

// sanitize converts a test name to a valid MySQL identifier suffix.
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

// TestAppliedNoMigrationsTable verifies Applied returns (nil, nil) when
// the _migrations table does not exist (MySQL error 1146). Defensive
// regression test against drivers that may surface the error lazily.
func TestAppliedNoMigrationsTable(t *testing.T) {
	conn := connect(t)

	m := mymigrate.New(conn)
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
		CREATE TABLE _migrations (id VARCHAR(16), name VARCHAR(255))
	`); err != nil {
		t.Fatalf("create table: %v", err)
	}
	if _, err := conn.ExecContext(ctx,
		`INSERT INTO _migrations (id, name) VALUES ('abc12345', '0001_init'), ('def67890', '0002_users')`,
	); err != nil {
		t.Fatalf("insert: %v", err)
	}

	m := mymigrate.New(conn)
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

	if _, err := conn.ExecContext(ctx, `CREATE TABLE _migrations (id VARCHAR(16), name VARCHAR(255))`); err != nil {
		t.Fatalf("create table: %v", err)
	}

	m := mymigrate.New(conn)
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
	conn := connect(t)
	ctx := t.Context()

	if _, err := conn.ExecContext(ctx, `CREATE TABLE _migrations (id VARCHAR(16), name VARCHAR(255))`); err != nil {
		t.Fatalf("create: %v", err)
	}

	m := mymigrate.New(conn)
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
