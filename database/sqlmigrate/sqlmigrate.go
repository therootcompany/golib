// Package sqlmigrate provides a database-agnostic SQL migration interface.
//
// Backend implementations (each a separate Go module):
//   - pgmigrate: PostgreSQL via pgx/v5
//   - mymigrate: MySQL/MariaDB via go-sql-driver/mysql
//   - litemigrate: SQLite via database/sql
//   - msmigrate: SQL Server via go-mssqldb
//   - shmigrate: POSIX shell script generation
package sqlmigrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"regexp"
	"slices"
	"strings"
)

// Sentinel errors for migration operations.
var (
	ErrMissingUp    = errors.New("missing up migration")
	ErrMissingDown  = errors.New("missing down migration")
	ErrWalkFailed   = errors.New("walking migrations")
	ErrExecFailed   = errors.New("migration exec failed")
	ErrQueryApplied = errors.New("querying applied migrations")
	ErrInvalidN     = errors.New("n must be positive or -1 for all")
)

// Migration represents a paired up/down migration.
type Migration struct {
	Name string // e.g. "2026-04-05-001000_create-todos"
	ID   string // 8-char hex from INSERT INTO _migrations, parsed by Collect
	Up   string // SQL content of the .up.sql file
	Down string // SQL content of the .down.sql file
}

// AppliedMigration represents a migration recorded in the _migrations table.
type AppliedMigration struct {
	ID   string
	Name string
}

// Status represents the current migration state.
type Status struct {
	Applied []string
	Pending []string
}

// Migrator executes migrations. Implementations handle the
// database-specific or output-specific details.
//
// Database backends should wrap each migration in a transaction when the
// database supports transactional DDL (e.g. PostgreSQL). For databases
// that do not (e.g. MySQL), the transaction provides atomicity for DML
// only — DDL statements are implicitly committed by the engine.
type Migrator interface {
	// ExecUp runs the up migration. For database migrators this executes
	// m.Up in a transaction (see package docs for DDL caveats). For shell
	// migrators this outputs a command referencing the .up.sql file.
	ExecUp(ctx context.Context, m Migration) error

	// ExecDown runs the down migration.
	ExecDown(ctx context.Context, m Migration) error

	// Applied returns all applied migrations from the _migrations table,
	// sorted lexicographically by name. Returns an empty slice (not an
	// error) if the migrations table or log does not exist yet.
	Applied(ctx context.Context) ([]AppliedMigration, error)
}

// idFromInsert extracts the hex ID from an INSERT INTO _migrations line.
// Matches: INSERT INTO _migrations (name, id) VALUES ('...', '<hex>');
var idFromInsert = regexp.MustCompile(
	`(?i)INSERT\s+INTO\s+_migrations\s*\(\s*name\s*,\s*id\s*\)\s*VALUES\s*\(\s*'[^']*'\s*,\s*'([0-9a-fA-F]+)'\s*\)`,
)

// Collect reads .up.sql and .down.sql files from fsys, pairs them by
// basename, and returns them sorted lexicographically by name.
// If the up SQL contains an INSERT INTO _migrations line, the hex ID
// is extracted and stored in Migration.ID.
func Collect(fsys fs.FS) ([]Migration, error) {
	ups := map[string]string{}
	downs := map[string]string{}

	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}

		name := d.Name()
		if base, ok := strings.CutSuffix(name, ".up.sql"); ok {
			b, readErr := fs.ReadFile(fsys, path)
			if readErr != nil {
				return readErr
			}
			ups[base] = string(b)
			return nil
		}
		if base, ok := strings.CutSuffix(name, ".down.sql"); ok {
			b, readErr := fs.ReadFile(fsys, path)
			if readErr != nil {
				return readErr
			}
			downs[base] = string(b)
			return nil
		}

		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWalkFailed, err)
	}

	var migrations []Migration
	for name, upSQL := range ups {
		downSQL, ok := downs[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingDown, name)
		}
		var id string
		if m := idFromInsert.FindStringSubmatch(upSQL); m != nil {
			id = m[1]
		}
		migrations = append(migrations, Migration{
			Name: name,
			ID:   id,
			Up:   upSQL,
			Down: downSQL,
		})
	}
	for name := range downs {
		if _, ok := ups[name]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingUp, name)
		}
	}

	slices.SortFunc(migrations, func(a, b Migration) int {
		return strings.Compare(a.Name, b.Name)
	})

	return migrations, nil
}

// NamesOnly builds a Migration slice from a list of names, with empty
// Up/Down content. Useful for shell-based runners that reference files
// on disk rather than executing SQL directly.
func NamesOnly(names []string) []Migration {
	migrations := make([]Migration, len(names))
	for i, name := range names {
		migrations[i] = Migration{Name: name}
	}
	return migrations
}

// isApplied returns true if the migration matches any applied entry by name or ID.
func isApplied(m Migration, applied []AppliedMigration) bool {
	for _, a := range applied {
		if a.Name == m.Name {
			return true
		}
		if m.ID != "" && a.ID != "" && a.ID == m.ID {
			return true
		}
	}
	return false
}

// findMigration looks up a migration by the applied entry's name or ID.
func findMigration(a AppliedMigration, byName map[string]Migration, byID map[string]Migration) (Migration, bool) {
	if m, ok := byName[a.Name]; ok {
		return m, true
	}
	if a.ID != "" {
		if m, ok := byID[a.ID]; ok {
			return m, true
		}
	}
	return Migration{}, false
}

// Up applies up to n pending migrations using the given Runner.
// If n < 0, applies all pending. If n == 0, returns ErrInvalidN.
// Returns the names of applied migrations.
func Up(ctx context.Context, r Migrator, migrations []Migration, n int) ([]string, error) {
	if n == 0 {
		return nil, ErrInvalidN
	}

	applied, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	var pending []Migration
	for _, m := range migrations {
		if !isApplied(m, applied) {
			pending = append(pending, m)
		}
	}

	if n < 0 {
		n = len(pending)
	}
	if n > len(pending) {
		n = len(pending)
	}

	var ran []string
	for _, m := range pending[:n] {
		if err := r.ExecUp(ctx, m); err != nil {
			return ran, fmt.Errorf("%s (up): %w", m.Name, err)
		}
		ran = append(ran, m.Name)
	}

	return ran, nil
}

// Down rolls back up to n applied migrations, most recent first.
// If n < 0, rolls back all applied. If n == 0, returns ErrInvalidN.
// Returns the names of rolled-back migrations.
func Down(ctx context.Context, r Migrator, migrations []Migration, n int) ([]string, error) {
	if n == 0 {
		return nil, ErrInvalidN
	}

	applied, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	byName := map[string]Migration{}
	byID := map[string]Migration{}
	for _, m := range migrations {
		byName[m.Name] = m
		if m.ID != "" {
			byID[m.ID] = m
		}
	}

	reversed := make([]AppliedMigration, len(applied))
	copy(reversed, applied)
	slices.Reverse(reversed)

	if n < 0 || n > len(reversed) {
		n = len(reversed)
	}

	var ran []string
	for _, a := range reversed[:n] {
		m, ok := findMigration(a, byName, byID)
		if !ok {
			return ran, fmt.Errorf("%w: %s", ErrMissingDown, a.Name)
		}
		if err := r.ExecDown(ctx, m); err != nil {
			return ran, fmt.Errorf("%s (down): %w", a.Name, err)
		}
		ran = append(ran, a.Name)
	}

	return ran, nil
}

// GetStatus returns applied and pending migration lists.
func GetStatus(ctx context.Context, r Migrator, migrations []Migration) (*Status, error) {
	applied, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	appliedNames := make([]string, len(applied))
	for i, a := range applied {
		appliedNames[i] = a.Name
	}

	var pending []string
	for _, m := range migrations {
		if !isApplied(m, applied) {
			pending = append(pending, m.Name)
		}
	}

	return &Status{
		Applied: appliedNames,
		Pending: pending,
	}, nil
}
