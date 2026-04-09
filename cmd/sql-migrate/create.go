package main

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

func create(state *State, desc string) error {
	dateStr := state.Date.Format("2006-01-02")
	entries, err := os.ReadDir(state.MigrationsDir)
	if err != nil {
		return err
	}

	maxNumber := 0
	datePrefix := dateStr + "-"
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !strings.HasPrefix(name, datePrefix) {
			continue
		}
		if !strings.HasSuffix(name, ".up.sql") {
			continue
		}
		if strings.HasSuffix(name, "_"+desc+".up.sql") {
			return fmt.Errorf("migration for %q already exists:\n   %s", desc, state.MigrationsDir+"/"+name)
		}
		if strings.HasSuffix(name, ".down.sql") {
			continue
		}

		parts := strings.SplitN(name, "-", 4)
		if len(parts) < 4 {
			continue
		}
		numDesc := strings.SplitN(parts[3], "_", 2)
		if len(numDesc) < 2 {
			continue
		}
		num, err := strconv.Atoi(numDesc[0])
		if err != nil {
			continue
		}

		if num > maxNumber {
			maxNumber = num
		}
	}

	number := maxNumber / 1_000
	number *= 1_000
	number += 1_000
	if number > 9_000 && number < 10_000 {
		fmt.Fprintf(os.Stderr, "Achievement Unlocked: It's over 9000!\n")
	}
	if number >= 999_999 {
		fmt.Fprintf(os.Stderr, "Error: cowardly refusing to generate such a suspiciously high number of migrations after running out of numbers\n")
		os.Exit(1)
	}

	basename := fmt.Sprintf("%s-%06d_%s", dateStr, number, desc)
	upPath := filepath.Join(state.MigrationsDir, basename+".up.sql")
	downPath := filepath.Join(state.MigrationsDir, basename+".down.sql")

	id := MustRandomHex(4)

	// Little Bobby Drop Tables says:
	// We trust the person running the migrations to not use malicious names.
	// (we don't want to embed db-specific logic here, and SQL doesn't define escaping)
	migrationInsert := fmt.Sprintf("INSERT INTO _migrations (name, id) VALUES ('%s', '%s');", basename, id)
	upContent := fmt.Appendf(nil, "-- %s (up)\nSELECT 'place your UP migration here';\n\n-- leave this as the last line\n%s\n", desc, migrationInsert)
	if err := os.WriteFile(upPath, upContent, 0644); err != nil {
		return fmt.Errorf("create up migration: %w", err)
	}
	migrationDelete := fmt.Sprintf("DELETE FROM _migrations WHERE id = '%s';", id)
	downContent := fmt.Appendf(nil, "-- %s (down)\nSELECT 'place your DOWN migration here';\n\n-- leave this as the last line\n%s\n", desc, migrationDelete)
	if err := os.WriteFile(downPath, downContent, 0644); err != nil {
		return fmt.Errorf("create down migration: %w", err)
	}

	fmt.Fprintf(os.Stderr, "    created pair %s\n", filepathUnclean(upPath))
	fmt.Fprintf(os.Stderr, "                 %s\n", filepathUnclean(downPath))
	return nil
}

func MustRandomHex(n int) string {
	s, err := RandomHex(n)
	if err != nil {
		panic(err)
	}
	return s
}

func RandomHex(n int) (string, error) {
	b := make([]byte, n) // 4 bytes = 8 hex chars
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
