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

// Migration identifies a migration by its name and optional hex ID.
type Migration struct {
	ID   string // 8-char hex from INSERT INTO _migrations, parsed by Collect
	Name string // e.g. "2026-04-05-001000_create-todos"
}

// Script is a Migration with its up and down SQL content, as returned by Collect.
type Script struct {
	Migration
	Up   string // SQL content of the .up.sql file
	Down string // SQL content of the .down.sql file
}

// Status represents the current migration state.
type Status struct {
	Applied []Migration
	Pending []Migration
}

// Migrator executes migrations. Implementations handle the
// database-specific or output-specific details.
type Migrator interface {
	// ExecUp runs the up migration SQL. For database migrators this
	// executes the SQL in a transaction. For shell migrators this
	// outputs a command referencing the .up.sql file.
	ExecUp(ctx context.Context, m Migration, sql string) error

	// ExecDown runs the down migration SQL.
	ExecDown(ctx context.Context, m Migration, sql string) error

	// Applied returns all applied migrations from the _migrations table,
	// sorted lexicographically by name. Returns an empty slice (not an
	// error) if the migrations table or log does not exist yet.
	Applied(ctx context.Context) ([]Migration, error)
}

// idFromInsert extracts the hex ID from an INSERT INTO _migrations line.
// Matches: INSERT INTO [schema.]_migrations (name, id) VALUES ('...', '<hex>');
var idFromInsert = regexp.MustCompile(
	`(?i)INSERT\s+INTO\s+(?:\w+\.)?_migrations\s*\(\s*name\s*,\s*id\s*\)\s*VALUES\s*\(\s*'[^']*'\s*,\s*'([0-9a-fA-F]+)'\s*\)`,
)

// Collect reads .up.sql and .down.sql files from fsys under subpath,
// pairs them by basename, and returns them sorted lexicographically by name.
// If subpath is "" or ".", the root of fsys is used.
// If the up SQL contains an INSERT INTO _migrations line, the hex ID
// is extracted and stored in Script.ID.
func Collect(fsys fs.FS, subpath string) ([]Script, error) {
	if subpath != "" && subpath != "." {
		var err error
		fsys, err = fs.Sub(fsys, subpath)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrWalkFailed, err)
		}
	}

	ups := map[string]string{}
	downs := map[string]string{}

	entries, err := fs.ReadDir(fsys, ".")
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrWalkFailed, err)
	}

	for _, d := range entries {
		if d.IsDir() {
			continue
		}

		name := d.Name()
		if base, ok := strings.CutSuffix(name, ".up.sql"); ok {
			b, readErr := fs.ReadFile(fsys, name)
			if readErr != nil {
				return nil, fmt.Errorf("%w: %w", ErrWalkFailed, readErr)
			}
			ups[base] = string(b)
			continue
		}
		if base, ok := strings.CutSuffix(name, ".down.sql"); ok {
			b, readErr := fs.ReadFile(fsys, name)
			if readErr != nil {
				return nil, fmt.Errorf("%w: %w", ErrWalkFailed, readErr)
			}
			downs[base] = string(b)
			continue
		}
	}

	var ddls []Script
	for name, upSQL := range ups {
		downSQL, ok := downs[name]
		if !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingDown, name)
		}
		var id string
		if m := idFromInsert.FindStringSubmatch(upSQL); m != nil {
			id = m[1]
		}
		ddls = append(ddls, Script{
			Migration: Migration{ID: id, Name: name},
			Up:        upSQL,
			Down:      downSQL,
		})
	}
	for name := range downs {
		if _, ok := ups[name]; !ok {
			return nil, fmt.Errorf("%w: %s", ErrMissingUp, name)
		}
	}

	slices.SortFunc(ddls, func(a, b Script) int {
		return strings.Compare(a.Name, b.Name)
	})

	return ddls, nil
}

// NamesOnly builds a Script slice from a list of names, with empty
// Up/Down content. Useful for shell-based runners that reference files
// on disk rather than executing SQL directly.
func NamesOnly(names []string) []Script {
	ddls := make([]Script, len(names))
	for i, name := range names {
		ddls[i] = Script{Migration: Migration{Name: name}}
	}
	return ddls
}

// isApplied returns true if the Script matches any applied entry by name or ID.
func isApplied(d Script, applied []Migration) bool {
	for _, a := range applied {
		if a.Name == d.Name {
			return true
		}
		if d.ID != "" && a.ID != "" && a.ID == d.ID {
			return true
		}
	}
	return false
}

// findScript looks up a Script by the applied entry's name or ID.
func findScript(a Migration, byName map[string]Script, byID map[string]Script) (Script, bool) {
	if d, ok := byName[a.Name]; ok {
		return d, true
	}
	if a.ID != "" {
		if d, ok := byID[a.ID]; ok {
			return d, true
		}
	}
	return Script{}, false
}

// Up applies up to n pending migrations using the given Migrator.
// If n < 0, applies all pending. If n == 0, returns ErrInvalidN.
// Returns the applied migrations.
func Up(ctx context.Context, r Migrator, ddls []Script, n int) ([]Migration, error) {
	if n == 0 {
		return nil, ErrInvalidN
	}

	applied, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	var pending []Script
	for _, d := range ddls {
		if !isApplied(d, applied) {
			pending = append(pending, d)
		}
	}

	if n < 0 {
		n = len(pending)
	}
	if n > len(pending) {
		n = len(pending)
	}

	var ran []Migration
	for _, d := range pending[:n] {
		if err := r.ExecUp(ctx, d.Migration, d.Up); err != nil {
			return ran, fmt.Errorf("%s (up): %w", d.Name, err)
		}
		ran = append(ran, d.Migration)
	}

	return ran, nil
}

// Down rolls back up to n applied migrations, most recent first.
// If n < 0, rolls back all applied. If n == 0, returns ErrInvalidN.
// Returns the rolled-back migrations.
func Down(ctx context.Context, r Migrator, ddls []Script, n int) ([]Migration, error) {
	if n == 0 {
		return nil, ErrInvalidN
	}

	applied, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	byName := map[string]Script{}
	byID := map[string]Script{}
	for _, d := range ddls {
		byName[d.Name] = d
		if d.ID != "" {
			byID[d.ID] = d
		}
	}

	reversed := make([]Migration, len(applied))
	copy(reversed, applied)
	slices.Reverse(reversed)

	if n < 0 || n > len(reversed) {
		n = len(reversed)
	}

	var ran []Migration
	for _, a := range reversed[:n] {
		d, ok := findScript(a, byName, byID)
		if !ok {
			return ran, fmt.Errorf("%w: %s", ErrMissingDown, a.Name)
		}
		if err := r.ExecDown(ctx, a, d.Down); err != nil {
			return ran, fmt.Errorf("%s (down): %w", a.Name, err)
		}
		ran = append(ran, a)
	}

	return ran, nil
}

// GetStatus returns applied and pending migration lists.
func GetStatus(ctx context.Context, r Migrator, ddls []Script) (*Status, error) {
	applied, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	var pending []Migration
	for _, d := range ddls {
		if !isApplied(d, applied) {
			pending = append(pending, d.Migration)
		}
	}

	return &Status{
		Applied: applied,
		Pending: pending,
	}, nil
}

// Latest applies all pending migrations. Equivalent to Up(ctx, r, ddls, -1).
func Latest(ctx context.Context, r Migrator, ddls []Script) ([]Migration, error) {
	return Up(ctx, r, ddls, -1)
}

// Drop rolls back all applied migrations. Equivalent to Down(ctx, r, ddls, -1).
func Drop(ctx context.Context, r Migrator, ddls []Script) ([]Migration, error) {
	return Down(ctx, r, ddls, -1)
}
