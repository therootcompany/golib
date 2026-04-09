package sqlmigrate_test

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/therootcompany/golib/database/sqlmigrate"
)

// migs builds []Migration from names (IDs empty).
func migs(names ...string) []sqlmigrate.Migration {
	out := make([]sqlmigrate.Migration, len(names))
	for i, n := range names {
		out[i] = sqlmigrate.Migration{Name: n}
	}
	return out
}

// names extracts just the Name field from a slice of Migration.
func names(ms []sqlmigrate.Migration) []string {
	out := make([]string, len(ms))
	for i, m := range ms {
		out[i] = m.Name
	}
	return out
}

// mockMigrator tracks applied migrations in memory.
type mockMigrator struct {
	applied   []sqlmigrate.Migration
	execErr   error // if set, ExecUp/ExecDown return this on every call
	upCalls   []string
	downCalls []string
}

func (m *mockMigrator) ExecUp(_ context.Context, mig sqlmigrate.Migration, _ string) error {
	m.upCalls = append(m.upCalls, mig.Name)
	if m.execErr != nil {
		return m.execErr
	}
	m.applied = append(m.applied, mig)
	slices.SortFunc(m.applied, func(a, b sqlmigrate.Migration) int {
		return strings.Compare(a.Name, b.Name)
	})
	return nil
}

func (m *mockMigrator) ExecDown(_ context.Context, mig sqlmigrate.Migration, _ string) error {
	m.downCalls = append(m.downCalls, mig.Name)
	if m.execErr != nil {
		return m.execErr
	}
	m.applied = slices.DeleteFunc(m.applied, func(a sqlmigrate.Migration) bool { return a.Name == mig.Name })
	return nil
}

func (m *mockMigrator) Applied(_ context.Context) ([]sqlmigrate.Migration, error) {
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
		ddls, err := sqlmigrate.Collect(fsys, ".")
		if err != nil {
			t.Fatal(err)
		}
		if len(ddls) != 2 {
			t.Fatalf("got %d ddls, want 2", len(ddls))
		}
		if ddls[0].Name != "001_first" {
			t.Errorf("first = %q, want %q", ddls[0].Name, "001_first")
		}
		if ddls[1].Name != "002_second" {
			t.Errorf("second = %q, want %q", ddls[1].Name, "002_second")
		}
		if ddls[0].Up != "CREATE TABLE a;" {
			t.Errorf("first.Up = %q", ddls[0].Up)
		}
		if ddls[0].Down != "DROP TABLE a;" {
			t.Errorf("first.Down = %q", ddls[0].Down)
		}
	})

	t.Run("parses ID from INSERT", func(t *testing.T) {
		fsys := fstest.MapFS{
			"001_init.up.sql":   {Data: []byte("CREATE TABLE a;\nINSERT INTO _migrations (name, id) VALUES ('001_init', 'abcd1234');")},
			"001_init.down.sql": {Data: []byte("DROP TABLE a;\nDELETE FROM _migrations WHERE id = 'abcd1234';")},
		}
		ddls, err := sqlmigrate.Collect(fsys, ".")
		if err != nil {
			t.Fatal(err)
		}
		if ddls[0].ID != "abcd1234" {
			t.Errorf("ID = %q, want %q", ddls[0].ID, "abcd1234")
		}
	})

	t.Run("no ID when no INSERT", func(t *testing.T) {
		fsys := fstest.MapFS{
			"001_init.up.sql":   {Data: []byte("CREATE TABLE a;")},
			"001_init.down.sql": {Data: []byte("DROP TABLE a;")},
		}
		ddls, err := sqlmigrate.Collect(fsys, ".")
		if err != nil {
			t.Fatal(err)
		}
		if ddls[0].ID != "" {
			t.Errorf("ID = %q, want empty", ddls[0].ID)
		}
	})

	t.Run("missing down", func(t *testing.T) {
		fsys := fstest.MapFS{
			"001_only-up.up.sql": {Data: []byte("CREATE TABLE x;")},
		}
		_, err := sqlmigrate.Collect(fsys, ".")
		if !errors.Is(err, sqlmigrate.ErrMissingDown) {
			t.Errorf("got %v, want ErrMissingDown", err)
		}
	})

	t.Run("missing up", func(t *testing.T) {
		fsys := fstest.MapFS{
			"001_only-down.down.sql": {Data: []byte("DROP TABLE x;")},
		}
		_, err := sqlmigrate.Collect(fsys, ".")
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
		ddls, err := sqlmigrate.Collect(fsys, ".")
		if err != nil {
			t.Fatal(err)
		}
		if len(ddls) != 1 {
			t.Fatalf("got %d ddls, want 1", len(ddls))
		}
	})

	t.Run("empty fs", func(t *testing.T) {
		fsys := fstest.MapFS{}
		ddls, err := sqlmigrate.Collect(fsys, ".")
		if err != nil {
			t.Fatal(err)
		}
		if len(ddls) != 0 {
			t.Fatalf("got %d ddls, want 0", len(ddls))
		}
	})
}

// --- NamesOnly ---

func TestNamesOnly(t *testing.T) {
	ns := []string{"001_init", "002_users"}
	ddls := sqlmigrate.NamesOnly(ns)
	if len(ddls) != 2 {
		t.Fatalf("got %d, want 2", len(ddls))
	}
	for i, d := range ddls {
		if d.Name != ns[i] {
			t.Errorf("[%d].Name = %q, want %q", i, d.Name, ns[i])
		}
		if d.Up != "" || d.Down != "" {
			t.Errorf("[%d] has non-empty content", i)
		}
	}
}

// --- Up ---

func TestUp(t *testing.T) {
	ctx := t.Context()
	ddls := []sqlmigrate.Script{
		{Migration: sqlmigrate.Migration{Name: "001_init"}, Up: "CREATE TABLE a;", Down: "DROP TABLE a;"},
		{Migration: sqlmigrate.Migration{Name: "002_users"}, Up: "CREATE TABLE b;", Down: "DROP TABLE b;"},
		{Migration: sqlmigrate.Migration{Name: "003_posts"}, Up: "CREATE TABLE c;", Down: "DROP TABLE c;"},
	}

	t.Run("apply all", func(t *testing.T) {
		m := &mockMigrator{}
		ran, err := sqlmigrate.Up(ctx, m, ddls, -1)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names(ran), []string{"001_init", "002_users", "003_posts"}) {
			t.Errorf("applied = %v", names(ran))
		}
	})

	t.Run("n=0 is error", func(t *testing.T) {
		m := &mockMigrator{}
		_, err := sqlmigrate.Up(ctx, m, ddls, 0)
		if !errors.Is(err, sqlmigrate.ErrInvalidN) {
			t.Errorf("got %v, want ErrInvalidN", err)
		}
	})

	t.Run("apply n", func(t *testing.T) {
		m := &mockMigrator{}
		ran, err := sqlmigrate.Up(ctx, m, ddls, 2)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names(ran), []string{"001_init", "002_users"}) {
			t.Errorf("applied = %v", names(ran))
		}
	})

	t.Run("none pending", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init", "002_users", "003_posts")}
		ran, err := sqlmigrate.Up(ctx, m, ddls, -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(ran) != 0 {
			t.Fatalf("applied %d, want 0", len(ran))
		}
	})

	t.Run("partial pending", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init")}
		ran, err := sqlmigrate.Up(ctx, m, ddls, -1)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names(ran), []string{"002_users", "003_posts"}) {
			t.Errorf("applied = %v", names(ran))
		}
	})

	t.Run("n exceeds pending", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init")}
		ran, err := sqlmigrate.Up(ctx, m, ddls, 99)
		if err != nil {
			t.Fatal(err)
		}
		if len(ran) != 2 {
			t.Fatalf("applied %d, want 2", len(ran))
		}
	})

	t.Run("exec error stops and returns partial", func(t *testing.T) {
		m := &failOnNthMigrator{failAt: 1}
		ran, err := sqlmigrate.Up(ctx, m, ddls, -1)
		if err == nil {
			t.Fatal("expected error")
		}
		if len(ran) != 1 {
			t.Errorf("applied %d before error, want 1", len(ran))
		}
	})

	t.Run("skips migration matched by ID", func(t *testing.T) {
		// DB has migration applied under old name, but same ID
		m := &mockMigrator{applied: []sqlmigrate.Migration{
			{Name: "001_old-name", ID: "aa11bb22"},
		}}
		idDDLs := []sqlmigrate.Script{
			{Migration: sqlmigrate.Migration{Name: "001_new-name", ID: "aa11bb22"}, Up: "CREATE TABLE a;", Down: "DROP TABLE a;"},
			{Migration: sqlmigrate.Migration{Name: "002_users"}, Up: "CREATE TABLE b;", Down: "DROP TABLE b;"},
		}
		ran, err := sqlmigrate.Up(ctx, m, idDDLs, -1)
		if err != nil {
			t.Fatal(err)
		}
		// Only 002_users should be applied; 001 is matched by ID
		if !slices.Equal(names(ran), []string{"002_users"}) {
			t.Errorf("applied = %v, want [002_users]", names(ran))
		}
	})
}

// failOnNthMigrator fails on the Nth ExecUp call (0-indexed).
type failOnNthMigrator struct {
	applied []sqlmigrate.Migration
	calls   int
	failAt  int
}

func (m *failOnNthMigrator) ExecUp(_ context.Context, mig sqlmigrate.Migration, _ string) error {
	if m.calls == m.failAt {
		m.calls++
		return errors.New("connection lost")
	}
	m.calls++
	m.applied = append(m.applied, mig)
	slices.SortFunc(m.applied, func(a, b sqlmigrate.Migration) int {
		return strings.Compare(a.Name, b.Name)
	})
	return nil
}

func (m *failOnNthMigrator) ExecDown(_ context.Context, mig sqlmigrate.Migration, _ string) error {
	m.applied = slices.DeleteFunc(m.applied, func(a sqlmigrate.Migration) bool { return a.Name == mig.Name })
	return nil
}

func (m *failOnNthMigrator) Applied(_ context.Context) ([]sqlmigrate.Migration, error) {
	return slices.Clone(m.applied), nil
}

// --- Down ---

func TestDown(t *testing.T) {
	ctx := t.Context()
	ddls := []sqlmigrate.Script{
		{Migration: sqlmigrate.Migration{Name: "001_init"}, Up: "CREATE TABLE a;", Down: "DROP TABLE a;"},
		{Migration: sqlmigrate.Migration{Name: "002_users"}, Up: "CREATE TABLE b;", Down: "DROP TABLE b;"},
		{Migration: sqlmigrate.Migration{Name: "003_posts"}, Up: "CREATE TABLE c;", Down: "DROP TABLE c;"},
	}

	t.Run("rollback all", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init", "002_users", "003_posts")}
		rolled, err := sqlmigrate.Down(ctx, m, ddls, -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(rolled) != 3 {
			t.Fatalf("rolled %d, want 3", len(rolled))
		}
		if rolled[0].Name != "003_posts" {
			t.Errorf("first rollback = %q, want 003_posts", rolled[0].Name)
		}
		if rolled[2].Name != "001_init" {
			t.Errorf("last rollback = %q, want 001_init", rolled[2].Name)
		}
	})

	t.Run("n=0 is error", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init", "002_users")}
		_, err := sqlmigrate.Down(ctx, m, ddls, 0)
		if !errors.Is(err, sqlmigrate.ErrInvalidN) {
			t.Errorf("got %v, want ErrInvalidN", err)
		}
	})

	t.Run("rollback n", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init", "002_users", "003_posts")}
		rolled, err := sqlmigrate.Down(ctx, m, ddls, 2)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names(rolled), []string{"003_posts", "002_users"}) {
			t.Errorf("rolled = %v", names(rolled))
		}
	})

	t.Run("none applied", func(t *testing.T) {
		m := &mockMigrator{}
		rolled, err := sqlmigrate.Down(ctx, m, ddls, -1)
		if err != nil {
			t.Fatal(err)
		}
		if len(rolled) != 0 {
			t.Fatalf("rolled %d, want 0", len(rolled))
		}
	})

	t.Run("exec error", func(t *testing.T) {
		m := &mockMigrator{
			applied: migs("001_init", "002_users"),
			execErr: errors.New("permission denied"),
		}
		rolled, err := sqlmigrate.Down(ctx, m, ddls, 1)
		if err == nil {
			t.Fatal("expected error")
		}
		if len(rolled) != 0 {
			t.Errorf("rolled %d on error, want 0", len(rolled))
		}
	})

	t.Run("unknown migration in applied", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init", "999_unknown")}
		_, err := sqlmigrate.Down(ctx, m, ddls, -1)
		if !errors.Is(err, sqlmigrate.ErrMissingScript) {
			t.Errorf("got %v, want ErrMissingScript", err)
		}
	})

	t.Run("n exceeds applied", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init")}
		rolled, err := sqlmigrate.Down(ctx, m, ddls, 99)
		if err != nil {
			t.Fatal(err)
		}
		if len(rolled) != 1 {
			t.Fatalf("rolled %d, want 1", len(rolled))
		}
	})

	t.Run("finds migration by ID when name changed", func(t *testing.T) {
		// DB has old name, file has new name, same ID
		m := &mockMigrator{applied: []sqlmigrate.Migration{
			{Name: "001_old-name", ID: "aa11bb22"},
		}}
		idDDLs := []sqlmigrate.Script{
			{Migration: sqlmigrate.Migration{Name: "001_new-name", ID: "aa11bb22"}, Up: "CREATE TABLE a;", Down: "DROP TABLE a;"},
		}
		rolled, err := sqlmigrate.Down(ctx, m, idDDLs, 1)
		if err != nil {
			t.Fatal(err)
		}
		if !slices.Equal(names(rolled), []string{"001_old-name"}) {
			t.Errorf("rolled = %v, want [001_old-name]", names(rolled))
		}
	})
}

// --- GetStatus ---

func TestGetStatus(t *testing.T) {
	ctx := t.Context()
	ddls := []sqlmigrate.Script{
		{Migration: sqlmigrate.Migration{Name: "001_init"}},
		{Migration: sqlmigrate.Migration{Name: "002_users"}},
		{Migration: sqlmigrate.Migration{Name: "003_posts"}},
	}

	t.Run("all pending", func(t *testing.T) {
		m := &mockMigrator{}
		status, err := sqlmigrate.GetStatus(ctx, m, ddls)
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
		m := &mockMigrator{applied: migs("001_init")}
		status, err := sqlmigrate.GetStatus(ctx, m, ddls)
		if err != nil {
			t.Fatal(err)
		}
		if len(status.Applied) != 1 || status.Applied[0].Name != "001_init" {
			t.Errorf("applied = %v", status.Applied)
		}
		if !slices.Equal(names(status.Pending), []string{"002_users", "003_posts"}) {
			t.Errorf("pending = %v", names(status.Pending))
		}
	})

	t.Run("all applied", func(t *testing.T) {
		m := &mockMigrator{applied: migs("001_init", "002_users", "003_posts")}
		status, err := sqlmigrate.GetStatus(ctx, m, ddls)
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
