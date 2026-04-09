package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/therootcompany/golib/database/sqlmigrate"
)

func (state *State) parseAndFixupBatches(text string) error {
	text = strings.TrimSpace(text)
	if text == "" {
		return nil
	}

	fixedUp := []string{}
	fixedDown := []string{}

	state.Lines = strings.Split(text, "\n")
	for i := range state.Lines {
		line := strings.TrimSpace(state.Lines[i])
		migration := commentStartRe.ReplaceAllString(line, "")
		migration = strings.TrimSpace(migration)
		if migration != "" {
			up, down, warn, err := fixupMigration(state.MigrationsDir, migration)
			if warn != nil {
				fmt.Fprintf(os.Stderr, "Warn: %s\n", warn)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
			state.Migrated = append(state.Migrated, migration)
			if up {
				fixedUp = append(fixedUp, migration)
			}
			if down {
				fixedDown = append(fixedDown, migration)
			}

		}
		state.Lines[i] = line
	}
	showFixes(fixedUp, fixedDown)

	return nil
}

func showFixes(fixedUp, fixedDown []string) {
	if len(fixedUp) > 0 {
		fmt.Fprintf(os.Stderr, "Fixup: appended missing 'INSERT INTO _migrations ...' to:\n")
		for _, up := range fixedUp {
			fmt.Fprintf(os.Stderr, "   %s\n", up)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}

	if len(fixedDown) > 0 {
		fmt.Fprintf(os.Stderr, "Fixup: appended missing 'DELETE FROM _migrations ...' to:\n")
		for _, down := range fixedDown {
			fmt.Fprintf(os.Stderr, "   %s\n", down)
		}
		fmt.Fprintf(os.Stderr, "\n")
	}
}

// attempts to add missing INSERT and DELETE without breaking what already works
func fixupMigration(dir string, basename string) (up, down bool, warn error, err error) {
	var id string

	var insertsOnUp bool
	upPath := filepath.Join(dir, basename+".up.sql")
	upScan, err := os.Open(upPath)
	if err != nil {
		return false, false, nil, fmt.Errorf("failed (up): %w", err)
	}
	defer upScan.Close()
	scanner := bufio.NewScanner(upScan)
	for scanner.Scan() {
		txt := scanner.Text()
		txt = strings.TrimSpace(txt)
		txt = strings.ToLower(txt)
		if strings.HasPrefix(txt, "insert into _migrations") {
			insertsOnUp = true
			break
		}
	}
	if !insertsOnUp {
		id = MustRandomHex(4)
		upScan.Close()
		upBytes, err := os.ReadFile(upPath)
		if err != nil {
			warn = fmt.Errorf("failed to add 'INSERT INTO _migrations ...' to %s: %w", upPath, err)
			return false, false, warn, nil
		}

		migrationInsertLn := fmt.Sprintf("\n-- leave this as the last line\nINSERT INTO _migrations (name, id) VALUES ('%s', '%s');\n", basename, id)
		upBytes = append(upBytes, []byte(migrationInsertLn)...)
		if err = os.WriteFile(upPath, upBytes, 0644); err != nil {
			warn = fmt.Errorf("failed to append 'INSERT INTO _migrations ...' to %s: %w", upPath, err)
			return false, false, warn, nil
		}
		up = true
	}

	var deletesOnDown bool
	downPath := filepath.Join(dir, basename+".down.sql")
	downScan, err := os.Open(downPath)
	if err != nil {
		return false, false, fmt.Errorf("failed (down): %w", err), nil
	}
	defer downScan.Close()
	scanner = bufio.NewScanner(downScan)
	for scanner.Scan() {
		txt := scanner.Text()
		txt = strings.TrimSpace(txt)
		txt = strings.ToLower(txt)
		if strings.HasPrefix(txt, "delete from _migrations") {
			deletesOnDown = true
			break
		}
	}
	if !deletesOnDown {
		if id == "" {
			return false, false, fmt.Errorf("must manually append \"DELETE FROM _migrations WHERE id = '<id>'\" to %s with id from %s", downPath, basename+"up.sql"), nil
		}
		downScan.Close()
		downFile, err := os.OpenFile(downPath, os.O_APPEND|os.O_WRONLY, 0o644)
		if err != nil {
			warn = fmt.Errorf("failed to append 'DELETE FROM _migrations ...' to %s: %v", downPath, err)
			return false, false, warn, nil
		}
		defer downFile.Close()

		migrationInsertLn := fmt.Sprintf("\nDELETE FROM _migrations WHERE id = '%s';\n", id)
		_, err = downFile.Write(([]byte(migrationInsertLn)))
		if err != nil {
			warn = fmt.Errorf("failed to add 'DELETE FROM _migrations ...' to %s: %w", downPath, err)
			return false, false, warn, nil
		}
		down = true
	}

	return up, down, nil, nil
}

// fixupAll runs fixupMigration on all known migrations (applied + pending).
func fixupAll(migrationsDir string, applied []string, migrations []sqlmigrate.Script) (fixedUp, fixedDown []string) {
	seen := map[string]bool{}
	var all []string
	for _, name := range applied {
		if !seen[name] {
			all = append(all, name)
			seen[name] = true
		}
	}
	for _, m := range migrations {
		if !seen[m.Name] {
			all = append(all, m.Name)
			seen[m.Name] = true
		}
	}

	for _, name := range all {
		up, down, warn, err := fixupMigration(migrationsDir, name)
		if warn != nil {
			fmt.Fprintf(os.Stderr, "Warn: %s\n", warn)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "%v\n", err)
		}
		if up {
			fixedUp = append(fixedUp, name)
		}
		if down {
			fixedDown = append(fixedDown, name)
		}
	}
	return fixedUp, fixedDown
}
