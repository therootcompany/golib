// Package sqlmigrate provides types and utilities for SQL migration files.
// It is database-agnostic — see pgmigrate for PostgreSQL execution,
// shmigrate for shell script generation.
package sqlmigrate

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
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
)

// Migration represents a paired up/down migration.
type Migration struct {
	Name string // e.g. "2026-04-05-001000_create-todos"
	Up   string // SQL content of the .up.sql file
	Down string // SQL content of the .down.sql file
}

// Status represents the current migration state.
type Status struct {
	Applied []string
	Pending []string
}

// Migrator executes migrations. Implementations handle the
// database-specific or output-specific details.
type Migrator interface {
	// ExecUp runs the up migration. For database migrators this executes
	// m.Up in a transaction. For shell migrators this outputs a command
	// referencing the .up.sql file.
	ExecUp(ctx context.Context, m Migration) error

	// ExecDown runs the down migration.
	ExecDown(ctx context.Context, m Migration) error

	// Applied returns the names of all applied migrations, sorted
	// lexicographically. Returns an empty slice (not an error) if the
	// migrations table or log does not exist yet.
	Applied(ctx context.Context) ([]string, error)
}

// Collect reads .up.sql and .down.sql files from fsys, pairs them by
// basename, and returns them sorted lexicographically by name.
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
		migrations = append(migrations, Migration{
			Name: name,
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

// Up applies up to n pending migrations using the given Runner.
// If n <= 0, applies all pending. Returns the names of applied migrations.
func Up(ctx context.Context, r Migrator, migrations []Migration, n int) ([]string, error) {
	appliedNames, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	var pending []Migration
	for _, m := range migrations {
		if !slices.Contains(appliedNames, m.Name) {
			pending = append(pending, m)
		}
	}

	if n <= 0 {
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
// If n <= 0, rolls back one. Returns the names of rolled-back migrations.
func Down(ctx context.Context, r Migrator, migrations []Migration, n int) ([]string, error) {
	appliedNames, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	if n <= 0 {
		n = 1
	}

	byName := map[string]Migration{}
	for _, m := range migrations {
		byName[m.Name] = m
	}

	reversed := make([]string, len(appliedNames))
	copy(reversed, appliedNames)
	slices.Reverse(reversed)

	if n > len(reversed) {
		n = len(reversed)
	}

	var ran []string
	for _, name := range reversed[:n] {
		m, ok := byName[name]
		if !ok {
			return ran, fmt.Errorf("%w: %s", ErrMissingDown, name)
		}
		if err := r.ExecDown(ctx, m); err != nil {
			return ran, fmt.Errorf("%s (down): %w", name, err)
		}
		ran = append(ran, name)
	}

	return ran, nil
}

// GetStatus returns applied and pending migration lists.
func GetStatus(ctx context.Context, r Migrator, migrations []Migration) (*Status, error) {
	appliedNames, err := r.Applied(ctx)
	if err != nil {
		return nil, err
	}

	var pending []string
	for _, m := range migrations {
		if !slices.Contains(appliedNames, m.Name) {
			pending = append(pending, m.Name)
		}
	}

	return &Status{
		Applied: appliedNames,
		Pending: pending,
	}, nil
}
