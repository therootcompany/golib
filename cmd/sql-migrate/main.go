//
// Written in 2025 by AJ ONeal <aj@therootcompany.com>
//
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.

// Package sql-migrate provides a simple SQL migrator that's easy to roll back or mix and match during development
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	version = "2.0.2"
)

const (
	defaultMigrationDir   = "./sql/migrations/"
	defaultLogPath        = "../migrations.log"
	sqlCommandPSQL        = `psql "$PG_URL" -v ON_ERROR_STOP=on -A -t --file %s`
	sqlCommandMariaDB     = `mariadb --defaults-extra-file="$MY_CNF" -s -N --raw < %s`
	sqlCommandMySQL       = `mysql --defaults-extra-file="$MY_CNF" -s -N --raw < %s`
	LOG_QUERY_NAME        = "_migrations.sql"
	M_MIGRATOR_NAME       = "0001-01-01-01000_init-migrations"
	M_MIGRATOR_UP_NAME    = "0001-01-01-01000_init-migrations.up.sql"
	M_MIGRATOR_DOWN_NAME  = "0001-01-01-01000_init-migrations.down.sql"
	defaultMigratorUpTmpl = `-- Config variables for sql-migrate (do not delete)
-- sql_command: %s
-- migrations_log: %s
--

CREATE TABLE IF NOT EXISTS _migrations (
   id CHAR(8) PRIMARY KEY DEFAULT encode(gen_random_bytes(4), 'hex'),
   name VARCHAR(80) NULL UNIQUE,
   applied_at TIMESTAMPTZ DEFAULT CURRENT_TIMESTAMP
);

-- note: to enable text-based tools to grep and sort we put 'name' before 'id'
--       grep -r 'INSERT INTO _migrations' ./sql/migrations/ | cut -d':' -f2 | sort
INSERT INTO _migrations (name, id) VALUES ('0001-01-01-01000_init-migrations', '00000001');
`
	defaultMigratorDown = `DELETE FROM _migrations WHERE id = '00000001';

DROP TABLE IF EXISTS _migrations;
`
	LOG_MIGRATIONS_QUERY = `-- note: CLI arguments must be passed to the sql command to keep output clean
SELECT name FROM _migrations ORDER BY name;
`
	shHeader = `#/bin/sh
set -e
set -u

if test -s ./.env; then
   . ./.env
fi
`
)

const helpText = `
sql-migrate v` + version + ` - a feature-branch-friendly SQL migrator

USAGE
   sql-migrate [-d sqldir] <command> [args]

EXAMPLE
   sql-migrate -d ./sql/migrations/ init --sql-command <psql|mariadb|mysql>
   sql-migrate -d ./sql/migrations/ create <kebab-case-description>
   sql-migrate -d ./sql/migrations/ status
   sql-migrate -d ./sql/migrations/ up 99
   sql-migrate -d ./sql/migrations/ down 1
   sql-migrate -d ./sql/migrations/ list

COMMANDS
   init          - creates migrations directory, initial migration, log file,
	                and query for migrations
   create        - creates a new, canonically-named up/down file pair in the
                   migrations directory, with corresponding insert
   status        - shows the same output as if processing a forward-migration
   up [n]        - create a script to run pending migrations (ALL by default)
   down [n]      - create a script to roll back migrations (ONE by default)
   list          - lists migrations

OPTIONS
   -d <migrations directory>  default: ./sql/migrations/
   --help                     show command-specific help

NOTES
   Migrations files are in the following format:
      <yyyy-mm-dd>-<number>_<name>.<up|down>.sql
      2020-01-01-1000_init-app.up.sql

	The initial migration file contains configuration variables:
		-- migrations_log: ./sql/migrations.log
		-- sql_command: psql "$PG_URL" -v ON_ERROR_STOP=on --no-align --file %s

	The log is generated on each migration file contains a list of all migrations:
      0001-01-01-001000_migrations.up.sql
      2020-12-31-001000_init-app.up.sql
      2020-12-31-001100_add-customer-tables.up.sql
      2020-12-31-002000_add-ALL-THE-TABLES.up.sql

   The 'create' generates an up/down pair of files using the current date and
      the number 1000. If either file exists, the number is incremented by 1000 and
      tried again.
`

var (
	nonWordRe      = regexp.MustCompile(`\W+`)
	commentStartRe = regexp.MustCompile(`(^|\s+)#.*`)
)

type State struct {
	Date          time.Time
	SQLCommand    string
	Lines         []string
	Migrated      []string
	MigrationsDir string
	LogPath       string
}

type MainConfig struct {
	migrationsDir string
	logPath       string
	sqlCommand    string
}

func main() {
	var cfg MainConfig
	var date = time.Now()

	if len(os.Args) < 2 {
		//nolint
		fmt.Printf("%s\n", helpText)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "help", "--help",
		"version", "--version", "-V":
		fmt.Printf("%s\n", helpText)
		os.Exit(0)
	default:
		// do nothing
	}

	mainArgs := os.Args[1:]
	fsMain := flag.NewFlagSet("", flag.ExitOnError)
	fsMain.StringVar(&cfg.migrationsDir, "d", defaultMigrationDir, "directory for migrations (where 0001-01-01_init-migrations.up.sql will be added)")
	if err := fsMain.Parse(mainArgs); err != nil {
		os.Exit(2)
	}

	var subcmd string
	// note: Args() includes any flags after the first non-flag arg
	// sql-migrate -d ./migs/ init --migrations-log ./migrations.log
	//    => init -f ./migrations.log
	subArgs := fsMain.Args()
	if len(subArgs) > 0 {
		subcmd = subArgs[0]
		subArgs = subArgs[1:]
	}

	var fsSub *flag.FlagSet
	switch subcmd {
	case "init":
		fsSub = flag.NewFlagSet("init", flag.ExitOnError)
		fsSub.StringVar(&cfg.logPath, "migrations-log", "", fmt.Sprintf("migration log file (default: %s) relative to and saved in %s", defaultLogPath, M_MIGRATOR_NAME))
		fsSub.StringVar(&cfg.sqlCommand, "sql-command", sqlCommandPSQL, "construct scripts with this to execute SQL files: 'psql', 'mysql', 'mariadb', or custom arguments")
	case "create", "up", "down", "status", "list":
		fsSub = flag.NewFlagSet(subcmd, flag.ExitOnError)
	default:
		log.Printf("unknown command %s", subcmd)
		fmt.Printf("%s\n", helpText)
		os.Exit(1)
	}
	if err := fsSub.Parse(subArgs); err != nil {
		os.Exit(2)
	}
	leafArgs := fsSub.Args()

	switch cfg.sqlCommand {
	case "", "posgres", "posgresql", "pg", "psql", "plpgsql":
		cfg.sqlCommand = sqlCommandPSQL
	case "mariadb":
		cfg.sqlCommand = sqlCommandMariaDB
	case "mysql", "my":
		cfg.sqlCommand = sqlCommandMySQL
	}

	if !strings.HasSuffix(cfg.migrationsDir, "/") {
		cfg.migrationsDir += "/"
	}

	if subcmd == "init" {
		mustInit(&cfg)
	}

	entries, err := os.ReadDir(cfg.migrationsDir)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: missing migrations directory. Run 'sql-migrate -d %q init' to create it.\n", cfg.migrationsDir)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "Error: couldn't list migrations directory: %v\n", err)
		os.Exit(1)
	}

	ups, downs := migrationsList(cfg.migrationsDir, entries)
	if !slices.Contains(ups, M_MIGRATOR_NAME) {
		fmt.Fprintf(os.Stderr, "Error: missing initial migration. Run 'sql-migrate -d %q init' to create %q.\n", cfg.migrationsDir, M_MIGRATOR_UP_NAME)
		os.Exit(1)
	}
	if !slices.Contains(downs, M_MIGRATOR_NAME) {
		fmt.Fprintf(os.Stderr, "Error: missing initial migration. Run 'sql-migrate -d %q init' to create %q.\n", cfg.migrationsDir, M_MIGRATOR_DOWN_NAME)
		os.Exit(1)
	}

	logQueryPath := filepath.Join(cfg.migrationsDir, LOG_QUERY_NAME)
	if !fileExists(logQueryPath) {
		fmt.Fprintf(os.Stderr, "Error: missing %q. Run 'sql-migrate -d %q init' to create it.\n", logQueryPath, cfg.migrationsDir)
		os.Exit(1)
	}

	mMigratorUpPath := filepath.Join(cfg.migrationsDir, M_MIGRATOR_UP_NAME)
	// mMigratorDownPath := filepath.Join(cfg.migrationsDir, M_MIGRATOR_DOWN_NAME)

	state := State{
		Date:          date,
		MigrationsDir: cfg.migrationsDir,
	}
	state.SQLCommand, state.LogPath, err = extractVars(mMigratorUpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't read config from initial migration: %v\n", err)
		os.Exit(1)
	}

	logText, err := os.ReadFile(state.LogPath)
	if err != nil {
		if !os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "Error: couldn't read migrations log %q: %v\n", state.LogPath, err)
			os.Exit(1)
		}

		if err := migrationsLogInit(&state, subcmd); err != nil {
			fmt.Fprintf(os.Stderr, "Error: couldn't create log file directory: %v\n", err)
			os.Exit(1)
		}
	}

	if err := state.parseAndFixupBatches(string(logText)); err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't read migrations log or fixup batches: %v\n", err)
		os.Exit(1)
	}

	switch subcmd {
	case "init":
		break
	case "create":
		if len(leafArgs) == 0 {
			log.Fatal("create requires a description")
		}
		desc := strings.Join(leafArgs, " ")
		desc = nonWordRe.ReplaceAllString(desc, " ")
		desc = strings.TrimSpace(desc)
		desc = nonWordRe.ReplaceAllString(desc, "-")
		desc = strings.ToLower(desc)
		err = create(&state, desc)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Error: couldn't create migration: %v\n", err)
			os.Exit(1)
		}
	case "status":
		if len(leafArgs) > 0 && subcmd != "create" {
			fmt.Fprintf(os.Stderr, "Error: unexpected args: %s\n", strings.Join(leafArgs, " "))
			os.Exit(1)
		}
		err = status(&state, ups)
		if err != nil {
			log.Fatal(err)
		}
	case "list":
		if len(leafArgs) > 0 && subcmd != "create" {
			fmt.Fprintf(os.Stderr, "Error: unexpected args: %s\n", strings.Join(leafArgs, " "))
			os.Exit(1)
		}
		fmt.Println("Ups:")
		if len(ups) == 0 {
			fmt.Println("   (none)")
		}
		for _, u := range ups {
			fmt.Println("  ", u)
		}
		fmt.Println("")
		fmt.Println("Downs:")
		if len(downs) == 0 {
			fmt.Println("   (none)")
		}
		for _, d := range downs {
			fmt.Println("  ", d)
		}
	case "up":
		var upN int
		switch len(leafArgs) {
		case 0:
			// ignore
		case 1:
			upN, err = strconv.Atoi(leafArgs[0])
			if err != nil || upN < 0 {
				fmt.Fprintf(os.Stderr, "Error: %s is not a positive number\n", leafArgs[0])
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "Error: unrecognized arguments %q \n", strings.Join(leafArgs, "\" \""))
			os.Exit(1)
		}

		err = up(&state, ups, upN)
		if err != nil {
			log.Fatal(err)
		}
	case "down":
		var downN int
		switch len(leafArgs) {
		case 0:
			// ignore
		case 1:
			downN, err = strconv.Atoi(leafArgs[0])
			if err != nil || downN < 0 {
				fmt.Fprintf(os.Stderr, "Error: %s is not a positive number\n", leafArgs[0])
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "Error: unrecognized arguments %q \n", strings.Join(leafArgs, "\" \""))
			os.Exit(1)
		}

		err = down(&state, downN)
		if err != nil {
			log.Fatal(err)
		}
	default:
		log.Printf("unknown command %s", subcmd)
		fmt.Printf("%s\n", helpText)
		os.Exit(1)
	}
}

func migrationsList(migrationsDir string, entries []os.DirEntry) (ups, downs []string) {
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") {
			if name != LOG_QUERY_NAME {
				fmt.Fprintf(os.Stderr, "   ignoring %s\n", filepathJoin(migrationsDir, name))
			}
			continue
		}

		if base, ok := strings.CutSuffix(name, ".up.sql"); ok {
			ups = append(ups, base)
			// TODO on ups add INSERT to file and to up migration if it doesn't exist
			continue
		}

		if base, ok := strings.CutSuffix(name, ".down.sql"); ok {
			downs = append(downs, base)
			continue
		}

		fmt.Fprintf(os.Stderr, "   unknown %s\n", filepathJoin(migrationsDir, name))
	}
	for _, down := range downs {
		// TODO on downs add INSERT to file and to up migration if it doesn't exist
		upName := strings.TrimSuffix(down, ".down.sql") + ".up.sql"
		companion := filepath.Join(migrationsDir, upName)
		if !fileExists(companion) {
			fmt.Fprintf(os.Stderr, "   missing '%s'\n", companion)
		}
	}

	sort.Strings(ups)
	sort.Strings(downs)
	return ups, downs
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false
		}
		fmt.Fprintf(os.Stderr, "Error: can't access %q\n", path)
		os.Exit(1)
		return false
	}

	return true
}

func filepathUnclean(path string) string {
	if !strings.HasPrefix(path, "/") {
		if !strings.HasPrefix(path, "./") && !strings.HasPrefix(path, "../") {
			path = "./" + path
		}
	}
	return path
}

func filepathJoin(src, dst string) string {
	return filepathUnclean(filepath.Join(src, dst))
}

// initializes all necessary files and directories
// - ./sql/migrations.log
//
// - ./sql/migrations
//
// - ./sql/migrations/0001-01-01-01000_init-migrations.up.sql
//   - migrations_log: ./sql/migrations.log
//   - sql_command: psql "$PG_URL" -v ON_ERROR_STOP=on --no-align --file %s
//
// - ./sql/migrations/0001-01-01-01000_init-migrations.down.sql
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
			fmt.Fprintf(os.Stderr, "Error: init failed to create %q: %v\n", cfg.migrationsDir, err)
			os.Exit(1)
		}
		if err = os.MkdirAll(cfg.migrationsDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "Error: init failed to read %q: %v\n", cfg.migrationsDir, err)
			os.Exit(1)
		}
	}

	ups, downs := migrationsList(cfg.migrationsDir, entries)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: init couldn't list existing migrations: %v\n", err)
		os.Exit(1)
	}

	mMigratorUpPath := filepath.Join(cfg.migrationsDir, M_MIGRATOR_UP_NAME)
	mMigratorDownPath := filepath.Join(cfg.migrationsDir, M_MIGRATOR_DOWN_NAME)

	// write config
	if slices.Contains(ups, M_MIGRATOR_NAME) {
		fmt.Fprintf(os.Stderr, "     found %s\n", filepath.Join(cfg.migrationsDir, M_MIGRATOR_UP_NAME))
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
	if created, err := initFile(logQueryPath, LOG_MIGRATIONS_QUERY); err != nil {
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
		fmt.Fprintf(os.Stderr, "Fixup: prepended missing 'INSERT INTO _migrations ...' to:\n")
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
	upContent := fmt.Appendf(nil, "-- leave this as the first line\n%s\n\n-- %s (up)\nSELECT 'place your UP migration here';\n", migrationInsert, desc)
	_ = os.WriteFile(upPath, upContent, 0644)
	migrationDelete := fmt.Sprintf("DELETE FROM _migrations WHERE id = '%s';", id)
	downContent := fmt.Appendf(nil, "-- %s (down)\nSELECT 'place your DOWN migration here';\n\n-- leave this as the last line\n%s\n", desc, migrationDelete)
	_ = os.WriteFile(downPath, downContent, 0644)

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

		migrationInsertLn := fmt.Sprintf("INSERT INTO _migrations (name, id) VALUES ('%s', '%s');\n\n", basename, id)
		upBytes = append([]byte(migrationInsertLn), upBytes...)
		if err = os.WriteFile(upPath, upBytes, 0644); err != nil {
			warn = fmt.Errorf("failed to prepend 'INSERT INTO _migrations ...' to %s: %w", upPath, err)
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

func up(state *State, ups []string, n int) error {
	var pending []string
	for _, mig := range ups {
		found := slices.Contains(state.Migrated, mig)
		if !found {
			pending = append(pending, mig)
		}
	}

	getMigsPath := filepath.Join(state.MigrationsDir, LOG_QUERY_NAME)
	getMigsPath = filepathUnclean(getMigsPath)
	getMigs := strings.Replace(state.SQLCommand, "%s", getMigsPath, 1)

	if len(pending) == 0 {
		fmt.Fprintf(os.Stderr, "# Already up-to-date\n")
		fmt.Fprintf(os.Stderr, "#\n")
		fmt.Fprintf(os.Stderr, "# To reload the migrations log:\n")
		fmt.Fprintf(os.Stderr, "# %s > %s\n", getMigs, filepathUnclean(state.LogPath))
		return nil
	}
	if n == 0 {
		n = len(pending)
	}

	fixedUp := []string{}
	fixedDown := []string{}

	fmt.Printf(shHeader)
	fmt.Println("")
	fmt.Println("# FORWARD / UP Migrations")
	fmt.Println("")
	for i, migration := range pending {
		if i >= n {
			break
		}

		path := filepath.Join(state.MigrationsDir, migration+".up.sql")
		path = filepathUnclean(path)
		{
			up, down, warn, err := fixupMigration(state.MigrationsDir, migration)
			if warn != nil {
				fmt.Fprintf(os.Stderr, "Warn: %s\n", warn)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
			if up {
				fixedUp = append(fixedUp, migration)
			}
			if down {
				fixedDown = append(fixedDown, migration)
			}
		}
		cmd := strings.Replace(state.SQLCommand, "%s", path, 1)
		fmt.Printf("# +%d %s\n", i+1, migration)
		fmt.Println(cmd)
		fmt.Println(getMigs + " > " + filepathUnclean(state.LogPath))
		fmt.Println("")
	}
	fmt.Println("cat", filepathUnclean(state.LogPath))

	showFixes(fixedUp, fixedDown)
	return nil
}

func down(state *State, n int) error {
	lines := make([]string, len(state.Lines))
	copy(lines, state.Lines)
	slices.Reverse(lines)

	getMigsPath := filepath.Join(state.MigrationsDir, LOG_QUERY_NAME)
	getMigsPath = filepathUnclean(getMigsPath)
	getMigs := strings.Replace(state.SQLCommand, "%s", getMigsPath, 1)

	if len(lines) == 0 {
		fmt.Fprintf(os.Stderr, "# No migration history\n")
		fmt.Fprintf(os.Stderr, "#\n")
		fmt.Fprintf(os.Stderr, "# To reload the migrations log:\n")
		fmt.Fprintf(os.Stderr, "# %s > %s\n", getMigs, filepathUnclean(state.LogPath))
		return nil
	}
	if n == 0 {
		n = 1
	}

	fixedUp := []string{}
	fixedDown := []string{}

	var applied []string
	for _, line := range lines {
		migration := commentStartRe.ReplaceAllString(line, "")
		migration = strings.TrimSpace(migration)
		if migration == "" {
			continue
		}
		applied = append(applied, migration)
	}

	fmt.Printf(shHeader)
	fmt.Println("")
	fmt.Println("# ROLLBACK / DOWN Migration")
	fmt.Println("")
	for i, migration := range applied {
		if i >= n {
			break
		}

		downPath := filepath.Join(state.MigrationsDir, migration+".down.sql")
		cmd := strings.Replace(state.SQLCommand, "%s", downPath, 1)
		fmt.Printf("\n# -%d %s\n", i+1, migration)
		if !fileExists(downPath) {
			fmt.Fprintf(os.Stderr, "# Warn: missing %s\n", filepathUnclean(downPath))
			fmt.Fprintf(os.Stderr, "#      (the migration will fail to run)\n")
			fmt.Printf("# ERROR: MISSING FILE\n")
		} else {
			up, down, warn, err := fixupMigration(state.MigrationsDir, migration)
			if warn != nil {
				fmt.Fprintf(os.Stderr, "Warn: %s\n", warn)
			}
			if err != nil {
				fmt.Fprintf(os.Stderr, "%v\n", err)
			}
			if up {
				fixedUp = append(fixedUp, migration)
			}
			if down {
				fixedDown = append(fixedDown, migration)
			}
		}

		fmt.Println(cmd)
		fmt.Println(getMigs + " > " + filepathUnclean(state.LogPath))
		fmt.Println("")
	}
	fmt.Println("cat", filepathUnclean(state.LogPath))

	showFixes(fixedUp, fixedDown)
	return nil
}

func status(state *State, ups []string) error {
	previous := make([]string, len(state.Lines))
	copy(previous, state.Lines)
	slices.Reverse(previous)

	fmt.Fprintf(os.Stderr, "migrations_dir: %s\n", filepathUnclean(state.MigrationsDir))
	fmt.Fprintf(os.Stderr, "migrations_log: %s\n", filepathUnclean(state.LogPath))
	fmt.Fprintf(os.Stderr, "sql_command: %s\n", state.SQLCommand)
	fmt.Fprintf(os.Stderr, "\n")
	fmt.Printf("# previous: %d\n", len(previous))
	for _, mig := range previous {
		fmt.Printf("   %s\n", mig)
	}
	if len(previous) == 0 {
		fmt.Println("   # (no previous migrations)")
	}
	fmt.Println("")
	var pending []string
	for _, mig := range ups {
		found := slices.Contains(state.Migrated, mig)
		if !found {
			pending = append(pending, mig)
		}
	}
	fmt.Printf("# pending: %d\n", len(pending))
	for _, mig := range pending {
		fmt.Printf("   %s\n", mig)
	}
	if len(pending) == 0 {
		fmt.Println("   # (no pending migrations)")
	}
	return nil
}
