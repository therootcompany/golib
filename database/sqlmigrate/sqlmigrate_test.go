package sqlmigrate_test

import (
	"context"
	"errors"
	"slices"
	"testing"
	"testing/fstest"

	"github.com/therootcompany/golib/database/sqlmigrate"
)

// mockMigrator tracks applied migrations in memory.
type mockMigrator struct {
	applied   []string
	execErr   error // if set, ExecUp/ExecDown return this on every call
	upCalls   []string
	downCalls []string
}

func (m *mockMigrator) ExecUp(_ context.Context, mig sqlmigrate.Migration) error {
	m.upCalls = append(m.upCalls, mig.Name)
	if m.execErr != nil {
		return m.execErr
	}
	m.applied = append(m.applied, mig.Name)
	slices.Sort(m.applied)
	return nil
}

func (m *mockMigrator) ExecDown(_ context.Context, mig sqlmigrate.Migration) error {
	m.downCalls = append(m.downCalls, mig.Name)
	if m.execErr != nil {
		return m.execErr
	}
	m.applied = slices.DeleteFunc(m.applied, func(s string) bool { return s == mig.Name })
	return nil
}

func (m *mockMigrator) Applied(_ context.Context) ([]string, error) {
	return slices.Clone(m.applied), nil
}

// --- Collect ---

func TestCollect(t *testing.T) {
	t.Run("pairs and sorts", func(t *testing.T) {
		fsys := fstest.MapFS{
			"002_second.up.sql":   {Data: []byte("CREATE TABLE b;")},
			"002_second.down.sql": {Data: []byte("DROP TABLE b;")},
			"001_first.up.sql":    {Data: []byte("CREATE TABLE a;")},
			"001_first.down.sql":  {Data: []byte("DROP TABLE a;")},
		}
		migrations, err := sqlmigrate.Collect(fsys)
		if err != nil {
			t.Fatal(err)
		}
		if len(migrations) != 2 {
			t.Fatalf("got %d migrations, want 2", len(migrations))
		}
		if migrations[0].Name != "001_first" {
			t.Errorf("first = %q, want %q", migrations[0].Name, "001_first")
		}
		if migrations[1].Name != "002_second" {
			t.Errorf("second = %q, want %q", migrations[1].Name, "002_second")
		}
		if migrations[0].Up != "CREATE TABLE a;" {
			t.Errorf("first.Up = %q", migrations[0].Up)
		}
		if migrations[0].Down != "DROP TABLE a;" {
			t.Errorf("first.Down = %q", migrations[0].Down)
		}
	})

	t.Run("missing down", func(t *testing.T) {
		fsys := fstest.MapFS{
			"001_only-up.up.sql": {Data: []byte("CREATE TABLE x;")},
		}
		_, err := sqlmigrate.Collect(fsys)
		if !errors.Is(err, sqlmigrate.ErrMissingDown) {
			t.Errorf("got %v, want ErrMissingDown", err)
		}
	})

	t.Run("missing up", func(t *testing.T) {
		fsys := fstest.MapFS{
			"001_only-down.down.sql": {Data: []byte("DROP TABLE x;")},
		}
		_, err := sqlmigrate.Collect(fsys)
		if !errors.Is(err, sqlmigrate.ErrMissingUp) {
			t.Errorf("got %v, want ErrMissingUp", err)
		}
	})

	t.Run("ignores non-sql files", func(t *testing.T) {
		fsys := fstest.MapFS{
			"001_init.up.sql":   {Data: []byte("UP")},
			"001_init.down.sql": {Data: []byte("DOWN")},
			"README.md":         {Data: []byte("# Migrations")},
			"_migrations.sql":   {Data: []byte("SELECT name FROM _migrations;")},
		}
		migrations, err := sqlmigrate.Collect(fsys)
		if err != nil {
			t.Fatal(err)
		}
		if len(migrations) != 1 {
			t.Fatalf("got %d migrations, want 1", len(migrations))
		}
	})

	t.Run("empty fs", func(t *testing.T) {
		fsys := fstest.MapFS{}
		migrations, err := sqlmigrate.Collect(fsys)
		if err != nil {
			t.Fatal(err)
		}
		if len(migrations) != 0 {
			t.Fatalf("got %d migrations, want 0", len(migrations))
		}
	})
}

// --- NamesOnly ---

func TestNamesOnly(t *testing.T) {
	names := []string{"001_init", "002_users"}
	migrations := sqlmigrate.NamesOnly(names)
	if len(migrations) != 2 {
		t.Fatalf("got %d, want 2", len(migrations))
	}
	for i, m := range migrations {
		if m.Name != names[i] {
			t.Errorf("[%d].Name = %q, want %q", i, m.Name, names[i])
		}
		if m.Up != "" || m.Down != "" {
			t.Errorf("[%d] has non-empty content", i)
		}
	}
}

// --- Up ---

func TestUp(t *testing.T) {
	ctx := t.Context()
	migrations := []sqlmigrate.Migration{
		{Name: "001_init", Up: "CREATE TABLE a;", Down: "DROP TABLE a;"},
		{Name: "002_users", Up: "CREATE TABLE b;", Down: "DROP TABLE b;"},
		{Name: "003_posts", Up: "CREATE TABLE c;", Down: "DROP TABLE c;"},
	}

	t.Run("apply all", func(t *testing.T) {
		m := &mockMigrator{}
		applied, err := sqlmigrate.Up(ctx, m, migrations, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(applied) != 3 {
			t.Fatalf("applied %d, want 3", len(applied))
		}
		if !slices.Equal(applied, []string{"001_init", "002_users", "003_posts"}) {
			t.Errorf("applied = %v", applied)
		}
	})

	t.Run("apply n", func(t *testing.T) {
		m := &mockMigrator{}
		applied, err := sqlmigrate.Up(ctx, m, migrations, 2)
		if err != nil {
			t.Fatal(err)
		}
		if len(applied) != 2 {
			t.Fatalf("applied %d, want 2", len(applied))
		}
		if applied[0] != "001_init" || applied[1] != "002_users" {
			t.Errorf("applied = %v", applied)
		}
	})

	t.Run("none pending", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init", "002_users", "003_posts"}}
		applied, err := sqlmigrate.Up(ctx, m, migrations, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(applied) != 0 {
			t.Fatalf("applied %d, want 0", len(applied))
		}
	})

	t.Run("partial pending", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init"}}
		applied, err := sqlmigrate.Up(ctx, m, migrations, 0)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(applied, []string{"002_users", "003_posts"}) {
			t.Errorf("applied = %v", applied)
		}
	})

	t.Run("n exceeds pending", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init"}}
		applied, err := sqlmigrate.Up(ctx, m, migrations, 99)
		if err != nil {
			t.Fatal(err)
		}
		if len(applied) != 2 {
			t.Fatalf("applied %d, want 2", len(applied))
		}
	})

	t.Run("exec error stops and returns partial", func(t *testing.T) {
		callCount := 0
		m := &mockMigrator{}
		// fail on second call
		origExecUp := m.ExecUp
		_ = origExecUp
		m2 := &failOnNthMigrator{failAt: 1}
		applied, err := sqlmigrate.Up(ctx, m2, migrations, 0)
		if err == nil {
			t.Fatal("expected error")
		}
		if len(applied) != 1 {
			t.Errorf("applied %d before error, want 1", len(applied))
		}
		_ = callCount
	})
}

// failOnNthMigrator fails on the Nth ExecUp call (0-indexed).
type failOnNthMigrator struct {
	applied []string
	calls   int
	failAt  int
}

func (m *failOnNthMigrator) ExecUp(_ context.Context, mig sqlmigrate.Migration) error {
	if m.calls == m.failAt {
		m.calls++
		return errors.New("connection lost")
	}
	m.calls++
	m.applied = append(m.applied, mig.Name)
	slices.Sort(m.applied)
	return nil
}

func (m *failOnNthMigrator) ExecDown(_ context.Context, mig sqlmigrate.Migration) error {
	m.applied = slices.DeleteFunc(m.applied, func(s string) bool { return s == mig.Name })
	return nil
}

func (m *failOnNthMigrator) Applied(_ context.Context) ([]string, error) {
	return slices.Clone(m.applied), nil
}

// --- Down ---

func TestDown(t *testing.T) {
	ctx := t.Context()
	migrations := []sqlmigrate.Migration{
		{Name: "001_init", Up: "CREATE TABLE a;", Down: "DROP TABLE a;"},
		{Name: "002_users", Up: "CREATE TABLE b;", Down: "DROP TABLE b;"},
		{Name: "003_posts", Up: "CREATE TABLE c;", Down: "DROP TABLE c;"},
	}

	t.Run("rollback all", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init", "002_users", "003_posts"}}
		rolled, err := sqlmigrate.Down(ctx, m, migrations, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rolled) != 3 {
			t.Fatalf("rolled %d, want 3", len(rolled))
		}
		// most recent first
		if rolled[0] != "003_posts" {
			t.Errorf("first rollback = %q, want 003_posts", rolled[0])
		}
		if rolled[2] != "001_init" {
			t.Errorf("last rollback = %q, want 001_init", rolled[2])
		}
	})

	t.Run("rollback n", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init", "002_users", "003_posts"}}
		rolled, err := sqlmigrate.Down(ctx, m, migrations, 2)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(rolled, []string{"003_posts", "002_users"}) {
			t.Errorf("rolled = %v", rolled)
		}
	})

	t.Run("none applied", func(t *testing.T) {
		m := &mockMigrator{}
		rolled, err := sqlmigrate.Down(ctx, m, migrations, 0)
		if err != nil {
			t.Fatal(err)
		}
		if len(rolled) != 0 {
			t.Fatalf("rolled %d, want 0", len(rolled))
		}
	})

	t.Run("exec error", func(t *testing.T) {
		m := &mockMigrator{
			applied: []string{"001_init", "002_users"},
			execErr: errors.New("permission denied"),
		}
		rolled, err := sqlmigrate.Down(ctx, m, migrations, 1)
		if err == nil {
			t.Fatal("expected error")
		}
		if len(rolled) != 0 {
			t.Errorf("rolled %d on error, want 0", len(rolled))
		}
	})

	t.Run("unknown migration in applied", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init", "999_unknown"}}
		_, err := sqlmigrate.Down(ctx, m, migrations, 0)
		if !errors.Is(err, sqlmigrate.ErrMissingDown) {
			t.Errorf("got %v, want ErrMissingDown", err)
		}
	})

	t.Run("n exceeds applied", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init"}}
		rolled, err := sqlmigrate.Down(ctx, m, migrations, 99)
		if err != nil {
			t.Fatal(err)
		}
		if len(rolled) != 1 {
			t.Fatalf("rolled %d, want 1", len(rolled))
		}
	})
}

// --- GetStatus ---

func TestGetStatus(t *testing.T) {
	ctx := t.Context()
	migrations := []sqlmigrate.Migration{
		{Name: "001_init"},
		{Name: "002_users"},
		{Name: "003_posts"},
	}

	t.Run("all pending", func(t *testing.T) {
		m := &mockMigrator{}
		status, err := sqlmigrate.GetStatus(ctx, m, migrations)
		if err != nil {
			t.Fatal(err)
		}
		if len(status.Applied) != 0 {
			t.Errorf("applied = %d, want 0", len(status.Applied))
		}
		if len(status.Pending) != 3 {
			t.Errorf("pending = %d, want 3", len(status.Pending))
		}
	})

	t.Run("partial", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init"}}
		status, err := sqlmigrate.GetStatus(ctx, m, migrations)
		if err != nil {
			t.Fatal(err)
		}
		if len(status.Applied) != 1 || status.Applied[0] != "001_init" {
			t.Errorf("applied = %v", status.Applied)
		}
		if !slices.Equal(status.Pending, []string{"002_users", "003_posts"}) {
			t.Errorf("pending = %v", status.Pending)
		}
	})

	t.Run("all applied", func(t *testing.T) {
		m := &mockMigrator{applied: []string{"001_init", "002_users", "003_posts"}}
		status, err := sqlmigrate.GetStatus(ctx, m, migrations)
		if err != nil {
			t.Fatal(err)
		}
		if len(status.Applied) != 3 {
			t.Errorf("applied = %d, want 3", len(status.Applied))
		}
		if len(status.Pending) != 0 {
			t.Errorf("pending = %d, want 0", len(status.Pending))
		}
	})
}
