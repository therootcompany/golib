package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"

	"github.com/therootcompany/golib/database/sqlmigrate/shmigrate"
)

// logMigrationsSelect returns the DB-specific SELECT line for _migrations.
// The output format is "id<tab>name" per row, compatible with shmigrate.Applied().
func logMigrationsSelect(sqlCommand string) (string, error) {
	var selectExpr string
	switch {
	case strings.Contains(sqlCommand, "psql"):
		selectExpr = "id || CHR(9) || name"
	case strings.Contains(sqlCommand, "mysql") || strings.Contains(sqlCommand, "mariadb"):
		selectExpr = "CONCAT(id, CHAR(9), name)"
	case strings.Contains(sqlCommand, "sqlite"):
		selectExpr = "id || CHAR(9) || name"
	case strings.Contains(sqlCommand, "sqlcmd"):
		selectExpr = "id + CHAR(9) + name"
	default:
		return "", fmt.Errorf("unrecognized --sql-command %q; cannot generate _migrations.sql", sqlCommand)
	}
	return fmt.Sprintf("SELECT %s FROM _migrations ORDER BY name;", selectExpr), nil
}

// initializes all necessary files and directories
// - ./sql/migrations.log
//
// - ./sql/migrations
//
// - ./sql/migrations/0001-01-01-001000_init-migrations.up.sql
//   - migrations_log: ./sql/migrations.log
//   - sql_command: psql "$PG_URL" -v ON_ERROR_STOP=on --no-align --tuples-only --file %s
//
// - ./sql/migrations/0001-01-01-001000_init-migrations.down.sql
func mustInit(cfg *MainConfig) {
	fmt.Fprintf(os.Stderr, "Initializing %q ...\n", cfg.migrationsDir)

	var resolvedLogPath = cfg.logPath
	if cfg.sqlCommand != "" && !strings.Contains(cfg.sqlCommand, "%s") {
		fmt.Fprintf(os.Stderr, "Error: --sql-command must contain a literal '%%s' to accept the path to the SQL file\n")
		os.Exit(1)
	}

	entries, err := os.ReadDir(cfg.migrationsDir)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: init failed to read %q: %v\n", cfg.migrationsDir, err)
			os.Exit(1)
		}
		if err = os.MkdirAll(cfg.migrationsDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error: init failed to create %q: %v\n", cfg.migrationsDir, err)
			os.Exit(1)
		}
	}

	ups, downs := migrationsList(cfg.migrationsDir, entries)

	mMigratorUpPath := filepath.Join(cfg.migrationsDir, M_MIGRATOR_UP_NAME)
	mMigratorDownPath := filepath.Join(cfg.migrationsDir, M_MIGRATOR_DOWN_NAME)

	// write config
	if slices.Contains(ups, M_MIGRATOR_NAME) {
		fmt.Fprintf(os.Stderr, "     found %s\n", filepathJoin(cfg.migrationsDir, M_MIGRATOR_UP_NAME))
	} else {
		if cfg.logPath == "" {
			migrationsParent := filepath.Dir(cfg.migrationsDir)
			resolvedLogPath = filepath.Join(migrationsParent, defaultLogPath)
			// resolvedLogPath, err = filepath.Rel(cfg.migrationsDir, cfg.logPath)
			// if err != nil {
			// 	fmt.Fprintf(os.Stderr, "Error: init couldn't resolve the migrations log relative to the migrations dir: %v\n", err)
			// 	os.Exit(1)
			// }
		}

		migratorUpQuery := fmt.Sprintf(defaultMigratorUpTmpl, cfg.sqlCommand, resolvedLogPath)
		if created, err := initFile(mMigratorUpPath, migratorUpQuery); err != nil {
			fmt.Fprintf(os.Stderr, "Error: init couldn't create initial up migration: %v\n", err)
			os.Exit(1)
		} else if created {
			fmt.Fprintf(os.Stderr, "   created %s\n", filepathUnclean(mMigratorUpPath))
		}
	}

	state := State{
		MigrationsDir: cfg.migrationsDir,
	}
	state.SQLCommand, state.LogPath, err = extractVars(mMigratorUpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: init couldn't read config from initial migration: %v\n", err)
		os.Exit(1)
	}
	if cfg.logPath != "" && filepath.Clean(cfg.logPath) != filepath.Clean(state.LogPath) {
		fmt.Fprintf(os.Stderr,
			"--migrations-log %q does not match %q from %q\n(drop the --migrations-log flag, or update the add migrations file)\n",
			cfg.logPath, state.LogPath, mMigratorUpPath,
		)
		os.Exit(1)
	}
	if cfg.sqlCommand != "" && cfg.sqlCommand != state.SQLCommand {
		fmt.Fprintf(os.Stderr,
			"--sql-command %q does not match %q from %q\n(drop the --sql-command flag, or update the add migrations file)\n",
			cfg.sqlCommand, state.SQLCommand, mMigratorUpPath,
		)
		os.Exit(1)
	}

	if slices.Contains(downs, M_MIGRATOR_NAME) {
		fmt.Fprintf(os.Stderr, "     found %s\n", filepathUnclean(mMigratorDownPath))
	} else {
		migratorDownQuery := defaultMigratorDown
		if created, err := initFile(mMigratorDownPath, migratorDownQuery); err != nil {
			fmt.Fprintf(os.Stderr, "Error: init couldn't create initial up migration: %v\n", err)
			os.Exit(1)
		} else if created {
			fmt.Fprintf(os.Stderr, "   created %s\n", filepathUnclean(mMigratorDownPath))
		}
	}

	logQueryPath := filepath.Join(state.MigrationsDir, LOG_QUERY_NAME)
	queryHeader := logMigrationsQueryNote
	if strings.Contains(state.SQLCommand, "sqlcmd") {
		queryHeader += logMigrationsQuerySQLCmdNote
	}
	selectLine, err := logMigrationsSelect(state.SQLCommand)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
	if created, err := initFile(logQueryPath, queryHeader+selectLine+"\n"); err != nil {
		fmt.Fprintf(os.Stderr, "Error: init couldn't create migrations query: %v\n", err)
		os.Exit(1)
	} else if created {
		fmt.Fprintf(os.Stderr, "   created %s\n", filepathUnclean(logQueryPath))
	} else {
		fmt.Fprintf(os.Stderr, "     found %s\n", filepathUnclean(logQueryPath))
	}

	if fileExists(state.LogPath) {
		fmt.Fprintf(os.Stderr, "     found %s\n", filepathUnclean(state.LogPath))
		fmt.Fprintf(os.Stderr, "done\n")
		return
	}
}

// maybeUpgradeLogQuery replaces the old name-only SELECT in _migrations.sql
// with the new id+name SELECT. Only the matching line is replaced; comments
// and other customizations are preserved.
func maybeUpgradeLogQuery(path, sqlCommand string) {
	b, err := os.ReadFile(path)
	if err != nil {
		return
	}
	var replaced bool
	var lines []string
	for line := range strings.SplitSeq(string(b), "\n") {
		if !replaced && strings.TrimSpace(line) == logMigrationsQueryPrev2_2_0 {
			newLine, err := logMigrationsSelect(sqlCommand)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Warn: %v\n", err)
				return
			}
			line = newLine
			replaced = true
		}
		lines = append(lines, line)
	}
	if !replaced {
		return
	}

	if err := os.WriteFile(path, []byte(strings.Join(lines, "\n")), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "Warn: couldn't upgrade %s: %v\n", path, err)
		return
	}
	fmt.Fprintf(os.Stderr, "   upgraded %s (added id to output)\n", filepathUnclean(path))
}

func initFile(path, contents string) (bool, error) {
	if fileExists(path) {
		return false, nil
	}

	if err := os.WriteFile(path, []byte(contents), 0644); err != nil {
		return false, err
	}

	return true, nil
}

func extractVars(curMigrationPath string) (sqlCommand string, logPath string, err error) {
	f, err := os.Open(curMigrationPath)
	if err != nil {
		return "", "", err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)

	var logPathRel string
	var logPathPrefix = "-- migrations_log:"
	var commandPrefix = "-- sql_command:"
	for scanner.Scan() {
		txt := scanner.Text()
		txt = strings.TrimSpace(txt)
		if strings.HasPrefix(txt, logPathPrefix) {
			logPathRel = strings.TrimSpace(txt[len(logPathPrefix):])
			continue
		} else if strings.HasPrefix(txt, commandPrefix) {
			sqlCommand = strings.TrimSpace(txt[len(commandPrefix):])
			continue
		}
	}

	if logPathRel == "" {
		return "", "", fmt.Errorf("Could not find '-- migrations_log: <relative-path>' in %q", curMigrationPath)
	}
	if sqlCommand == "" {
		return "", "", fmt.Errorf("Could not find '-- sql_command: <args>' in %q", curMigrationPath)
	}

	// migrationsDir := filepath.Dir(curMigrationPath)
	// logPath = filepath.Join(migrationsDir, logPathRel)
	// return sqlCommand, logPath, nil
	return sqlCommand, logPathRel, nil
}

func migrationsLogInit(state *State, subcmd string) error {
	logDir := filepath.Dir(state.LogPath)
	if err := os.MkdirAll(logDir, 0755); err != nil {
		return err
	}

	if subcmd != "up" {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Run the first migration to complete the initialization:\n")
		fmt.Fprintf(os.Stderr, "(you'll need to provide DB credentials via .env or export)\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "   sql-migrate -d %q up > ./up.sh && sh ./up.sh\n", state.MigrationsDir)
		fmt.Fprintf(os.Stderr, "\n")
	}
	return nil
}

func syncLog(runner *shmigrate.Migrator) {
	syncCmd := strings.Replace(runner.SqlCommand, "%s", filepathUnclean(runner.LogQueryPath), 1)
	logPath := filepathUnclean(runner.LogPath)

	fmt.Printf(shmigrate.ShHeader)
	fmt.Println("")
	fmt.Println("# SYNC: reload migrations log from DB")
	fmt.Printf("%s > %s || true\n", syncCmd, logPath)
	fmt.Printf("cat %s\n", logPath)
}
