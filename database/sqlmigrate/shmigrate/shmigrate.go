// Package shmigrate implements sqlmigrate.Runner by generating POSIX
// shell commands that reference migration files on disk. It is used by
// the sql-migrate CLI to produce scripts that can be piped to sh.
package shmigrate

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/therootcompany/golib/database/sqlmigrate"
)

// ShHeader is the standard header for generated shell scripts.
const ShHeader = `#!/bin/sh
set -e
set -u

if test -s ./.env; then
    . ./.env
fi
`

// Migrator generates shell scripts for migration execution.
// It implements sqlmigrate.Migrator so it can be used with
// sqlmigrate.Up, sqlmigrate.Down, and sqlmigrate.GetStatus.
type Migrator struct {
	// Writer receives the generated shell script.
	Writer io.Writer

	// SqlCommand is the shell command template with %s for the file path.
	// Example: `psql "$PG_URL" -v ON_ERROR_STOP=on -A -t --file %s`
	SqlCommand string

	// MigrationsDir is the path to the migrations directory on disk.
	MigrationsDir string

	// LogQueryPath is the path to the _migrations.sql query file.
	// Used to sync the migrations log after each migration.
	LogQueryPath string

	// LogPath is the path to the migrations.log file.
	LogPath string

	// FS is an optional filesystem for reading the migrations log.
	// When nil, the OS filesystem is used.
	FS fs.FS

	counter int
}

// verify interface compliance at compile time
var _ sqlmigrate.Migrator = (*Migrator)(nil)

// ExecUp outputs a shell command to run the .up.sql migration file.
func (r *Migrator) ExecUp(ctx context.Context, m sqlmigrate.Migration) error {
	r.counter++
	return r.exec(m.Name, ".up.sql", fmt.Sprintf("+%d", r.counter))
}

// ExecDown outputs a shell command to run the .down.sql migration file.
func (r *Migrator) ExecDown(ctx context.Context, m sqlmigrate.Migration) error {
	r.counter++
	return r.exec(m.Name, ".down.sql", fmt.Sprintf("-%d", r.counter))
}

func (r *Migrator) exec(name, suffix, label string) error {
	path := unclean(filepath.Join(r.MigrationsDir, name+suffix))
	cmd := strings.Replace(r.SqlCommand, "%s", path, 1)

	syncCmd := strings.Replace(r.SqlCommand, "%s", unclean(r.LogQueryPath), 1)
	logPath := unclean(r.LogPath)

	fmt.Fprintf(r.Writer, "# %s %s\n", label, name)
	fmt.Fprintln(r.Writer, cmd)
	fmt.Fprintf(r.Writer, "%s > %s || true\n", syncCmd, logPath)
	fmt.Fprintln(r.Writer)

	return nil
}

// Applied reads the migrations log file and returns applied migration names.
// Returns an empty slice if the file does not exist. When FS is set, reads
// from that filesystem; otherwise reads from the OS filesystem.
func (r *Migrator) Applied(ctx context.Context) ([]string, error) {
	var f io.ReadCloser
	var err error
	if r.FS != nil {
		f, err = r.FS.Open(r.LogPath)
	} else {
		f, err = os.Open(r.LogPath)
	}
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("reading migrations log: %w", err)
	}
	defer f.Close()

	var names []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		// strip inline comments
		if idx := strings.Index(line, "#"); idx >= 0 {
			line = strings.TrimSpace(line[:idx])
		}
		if line != "" {
			names = append(names, line)
		}
	}

	return names, nil
}

// Reset resets the migration counter. Call between Up and Down
// if generating both in the same script.
func (r *Migrator) Reset() {
	r.counter = 0
}

// unclean ensures a relative path starts with ./ or ../ so it
// is not interpreted as a command name in shell scripts.
func unclean(path string) string {
	if strings.HasPrefix(path, "/") {
		return path
	}
	if strings.HasPrefix(path, "./") || strings.HasPrefix(path, "../") {
		return path
	}
	return "./" + path
}
