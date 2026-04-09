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
	"context"
	"flag"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/therootcompany/golib/database/sqlmigrate"
	"github.com/therootcompany/golib/database/sqlmigrate/shmigrate"
)

// replaced by goreleaser / ldflags
var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01"
)

const (
	defaultMigrationDir   = "./sql/migrations/"
	defaultLogPath        = "../migrations.log"
	sqlCommandPSQL        = `psql "$PG_URL" -v ON_ERROR_STOP=on --no-align --tuples-only --file %s`
	sqlCommandMariaDB     = `mariadb --defaults-extra-file="$MY_CNF" --silent --skip-column-names --raw < %s`
	sqlCommandMySQL       = `mysql --defaults-extra-file="$MY_CNF" --silent --skip-column-names --raw < %s`
	sqlCommandSQLite      = `sqlite3 "$SQLITE_PATH" < %s`
	sqlCommandSQLCmd      = `sqlcmd --exit-on-error --headers -1 --trim-spaces --encrypt-connection strict --input-file %s`
	LOG_QUERY_NAME        = "_migrations.sql"
	M_MIGRATOR_NAME       = "0001-01-01-001000_init-migrations"
	M_MIGRATOR_UP_NAME    = "0001-01-01-001000_init-migrations.up.sql"
	M_MIGRATOR_DOWN_NAME  = "0001-01-01-001000_init-migrations.down.sql"
	defaultMigratorUpTmpl = `-- Config variables for sql-migrate (do not delete)
-- sql_command: %s
-- migrations_log: %s
--

CREATE TABLE IF NOT EXISTS _migrations (
   id CHAR(8) PRIMARY KEY,
   name VARCHAR(80) NULL UNIQUE,
   applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- note: to enable text-based tools to grep and sort we put 'name' before 'id'
--       grep -r 'INSERT INTO _migrations' ./sql/migrations/ | cut -d':' -f2 | sort
INSERT INTO _migrations (name, id) VALUES ('0001-01-01-001000_init-migrations', '00000001');
`
	defaultMigratorDown = `DELETE FROM _migrations WHERE id = '00000001';

DROP TABLE IF EXISTS _migrations;
`
	// Used for detection during auto-upgrade.
	logMigrationsQueryPrev2_2_0 = `SELECT name FROM _migrations ORDER BY name;`

	logMigrationsQueryNote       = "-- note: CLI arguments must be passed to the sql command to keep output machine-readable\n"
	logMigrationsQuerySQLCmdNote = "-- connection: set SQLCMDSERVER, SQLCMDDATABASE, SQLCMDUSER, SQLCMDPASSWORD in .env\n"
)

// printVersion displays the version, commit, and build date.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "sql-migrate v%s %s (%s)\n", version, commit[:7], date)
}

var helpText = `
sql-migrate - a feature-branch-friendly SQL migrator

USAGE
   sql-migrate [-d sqldir] <command> [args]

EXAMPLE
   sql-migrate -d ./sql/migrations/ init --sql-command <psql|mariadb|mysql|sqlite|sqlcmd>
   sql-migrate -d ./sql/migrations/ create <kebab-case-description>
   sql-migrate -d ./sql/migrations/ sync
   sql-migrate -d ./sql/migrations/ status
   sql-migrate -d ./sql/migrations/ up 99
   sql-migrate -d ./sql/migrations/ down 1
   sql-migrate -d ./sql/migrations/ list

COMMANDS
   init          - creates migrations directory, initial migration, log file,
	                and query for migrations
   create        - creates a new, canonically-named up/down file pair in the
                   migrations directory, with corresponding insert
   sync          - create a script to reload migrations.log from the DB
                   (run after upgrading sql-migrate)
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
		-- sql_command: psql "$PG_URL" -v ON_ERROR_STOP=on --no-align --tuples-only --file %s

	The log is generated on each migration file contains a list of all migrations:
      0001-01-01-001000_init-migrations.up.sql
      2020-12-31-001000_init-app.up.sql
      2020-12-31-001100_add-customer-tables.up.sql
      2020-12-31-002000_add-ALL-THE-TABLES.up.sql

   The 'create' generates an up/down pair of files using the current date and
      the number 1000. If either file exists, the number is incremented by 1000 and
      tried again.

NOTE: POSTGRES SCHEMAS
   Set PGOPTIONS to target a specific PostgreSQL schema:

      PGOPTIONS="-c search_path=tenant123" sql-migrate up | sh

   Each schema gets its own _migrations table, so tenants are migrated
   independently. PGOPTIONS is supported by psql and all libpq clients.

NOTE: SQL SERVER (go-sqlcmd)
   Requires the modern sqlcmd (go-mssqldb), not the legacy ODBC version.
   Install: brew install sqlcmd (macOS), winget install sqlcmd (Windows)

   The default uses --encrypt-connection strict (TDS 8.0), which provides
   TLS-first on TCP with ALPN 'tds/8.0' and SNI — required for proper TLS
   termination at load balancers and reverse proxies.

   Set these SQLCMD environment variables in your .env file:

      SQLCMDSERVER='host\instance'   # or host,port (e.g. localhost,1433)
      SQLCMDDATABASE=myapp
      SQLCMDUSER=sa
      SQLCMDPASSWORD=secret

   SQLCMDSERVER is the instance, not just the host. Common formats:
      SQLCMDSERVER=localhost              # default instance
      SQLCMDSERVER='localhost\SQLEXPRESS' # named instance (quote the backslash)
      SQLCMDSERVER='localhost,1433'       # host and port

   sqlcmd reads these automatically — no credentials in the command template.

   For local development without TLS:
      --sql-command 'sqlcmd --exit-on-error --headers -1 --trim-spaces --encrypt-connection disable --input-file %s'

UPGRADING
   After upgrading sql-migrate, run sync to refresh the log format:
      sql-migrate -d ./sql/migrations/ sync | sh
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
	var today = time.Now()

	if len(os.Args) < 2 {
		printVersion(os.Stdout)
		fmt.Println("")
		fmt.Printf("%s\n", helpText)
		os.Exit(0)
	}

	switch os.Args[1] {
	case "-V", "-version", "--version", "version":
		printVersion(os.Stdout)
		os.Exit(0)
	case "help", "-help", "--help":
		printVersion(os.Stdout)
		fmt.Println("")
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
		fsSub.StringVar(&cfg.sqlCommand, "sql-command", sqlCommandPSQL, "construct scripts with this to execute SQL files: 'psql', 'mysql', 'mariadb', 'sqlite', 'sqlcmd', or custom arguments")
	case "create", "sync", "up", "down", "status", "list":
		fsSub = flag.NewFlagSet(subcmd, flag.ExitOnError)
	default:
		log.Printf("unknown command %s", subcmd)
		printVersion(os.Stderr)
		fmt.Fprintf(os.Stderr, "%s\n", helpText)
		os.Exit(1)
	}
	if err := fsSub.Parse(subArgs); err != nil {
		os.Exit(2)
	}
	leafArgs := fsSub.Args()

	switch cfg.sqlCommand {
	case "", "postgres", "postgresql", "pg", "psql", "plpgsql":
		cfg.sqlCommand = sqlCommandPSQL
	case "mariadb":
		cfg.sqlCommand = sqlCommandMariaDB
	case "mysql", "my":
		cfg.sqlCommand = sqlCommandMySQL
	case "sqlite", "sqlite3", "lite":
		cfg.sqlCommand = sqlCommandSQLite
	case "sqlcmd", "mssql", "sqlserver":
		cfg.sqlCommand = sqlCommandSQLCmd
	default:
		// leave as provided by the user
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
		Date:          today,
		MigrationsDir: cfg.migrationsDir,
	}
	state.SQLCommand, state.LogPath, err = extractVars(mMigratorUpPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: couldn't read config from initial migration: %v\n", err)
		os.Exit(1)
	}

	// auto-upgrade _migrations.sql to include id in output
	maybeUpgradeLogQuery(logQueryPath, state.SQLCommand)

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

	ctx := context.Background()
	runner := &shmigrate.Migrator{
		Writer:        os.Stdout,
		SqlCommand:    state.SQLCommand,
		MigrationsDir: state.MigrationsDir,
		LogQueryPath:  filepath.Join(state.MigrationsDir, LOG_QUERY_NAME),
		LogPath:       state.LogPath,
	}
	migrations := sqlmigrate.NamesOnly(ups)

	switch subcmd {
	case "init":
		break
	case "sync":
		syncLog(runner)
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
		if len(leafArgs) > 0 {
			fmt.Fprintf(os.Stderr, "Error: unexpected args: %s\n", strings.Join(leafArgs, " "))
			os.Exit(1)
		}
		if err := cmdStatus(ctx, &state, runner, migrations); err != nil {
			log.Fatal(err)
		}
	case "list":
		if len(leafArgs) > 0 {
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
		upN := -1
		switch len(leafArgs) {
		case 0:
			// no arg: apply all pending
		case 1:
			upN, err = strconv.Atoi(leafArgs[0])
			if err != nil || upN < 1 {
				fmt.Fprintf(os.Stderr, "Error: %s is not a positive number\n", leafArgs[0])
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "Error: unrecognized arguments %q \n", strings.Join(leafArgs, "\" \""))
			os.Exit(1)
		}

		if err := cmdUp(ctx, &state, runner, migrations, upN); err != nil {
			log.Fatal(err)
		}
	case "down":
		downN := 1
		switch len(leafArgs) {
		case 0:
			// default: roll back one
		case 1:
			downN, err = strconv.Atoi(leafArgs[0])
			if err != nil || downN < 1 {
				fmt.Fprintf(os.Stderr, "Error: %s is not a positive number\n", leafArgs[0])
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "Error: unrecognized arguments %q \n", strings.Join(leafArgs, "\" \""))
			os.Exit(1)
		}

		if err := cmdDown(ctx, &state, runner, migrations, downN); err != nil {
			log.Fatal(err)
		}
	default:
		log.Printf("unknown command %s", subcmd)
		printVersion(os.Stderr)
		fmt.Fprintf(os.Stderr, "%s\n", helpText)
		os.Exit(1)
	}
}

func migrationsList(migrationsDir string, entries []os.DirEntry) (ups, downs []string) {
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") || strings.HasPrefix(name, "_") || strings.HasPrefix(name, "+") {
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

func cmdUp(ctx context.Context, state *State, runner *shmigrate.Migrator, migrations []sqlmigrate.Script, n int) error {
	// fixup pending migrations before generating the script
	fixedUp, fixedDown := fixupAll(state.MigrationsDir, state.Migrated, migrations)

	status, err := sqlmigrate.GetStatus(ctx, runner, migrations)
	if err != nil {
		return err
	}

	if len(status.Pending) == 0 {
		syncCmd := strings.Replace(runner.SqlCommand, "%s", filepathUnclean(runner.LogQueryPath), 1)
		fmt.Fprintf(os.Stderr, "# Already up-to-date\n")
		fmt.Fprintf(os.Stderr, "#\n")
		fmt.Fprintf(os.Stderr, "# To reload the migrations log:\n")
		fmt.Fprintf(os.Stderr, "# %s > %s\n", syncCmd, filepathUnclean(runner.LogPath))
		return nil
	}

	fmt.Printf(shmigrate.ShHeader)
	fmt.Println("")
	fmt.Println("# FORWARD / UP Migrations")
	fmt.Println("")

	applied, err := sqlmigrate.Up(ctx, runner, migrations, n)
	if err != nil {
		return err
	}
	_ = applied

	fmt.Println("cat", filepathUnclean(runner.LogPath))

	showFixes(fixedUp, fixedDown)
	return nil
}

func cmdDown(ctx context.Context, state *State, runner *shmigrate.Migrator, migrations []sqlmigrate.Script, n int) error {
	// fixup applied migrations before generating the script
	fixedUp, fixedDown := fixupAll(state.MigrationsDir, state.Migrated, migrations)

	status, err := sqlmigrate.GetStatus(ctx, runner, migrations)
	if err != nil {
		return err
	}

	if len(status.Applied) == 0 {
		syncCmd := strings.Replace(runner.SqlCommand, "%s", filepathUnclean(runner.LogQueryPath), 1)
		fmt.Fprintf(os.Stderr, "# No migration history\n")
		fmt.Fprintf(os.Stderr, "#\n")
		fmt.Fprintf(os.Stderr, "# To reload the migrations log:\n")
		fmt.Fprintf(os.Stderr, "# %s > %s\n", syncCmd, filepathUnclean(runner.LogPath))
		return nil
	}

	fmt.Printf(shmigrate.ShHeader)
	fmt.Println("")
	fmt.Println("# ROLLBACK / DOWN Migration")
	fmt.Println("")

	// check for missing down files before generating script
	reversed := make([]sqlmigrate.Migration, len(status.Applied))
	copy(reversed, status.Applied)
	slices.Reverse(reversed)
	limit := n
	if limit <= 0 {
		limit = 1
	}
	if limit > len(reversed) {
		limit = len(reversed)
	}
	for _, a := range reversed[:limit] {
		downPath := filepath.Join(state.MigrationsDir, a.Name+".down.sql")
		if !fileExists(downPath) {
			fmt.Fprintf(os.Stderr, "# Warn: missing %s\n", filepathUnclean(downPath))
			fmt.Fprintf(os.Stderr, "#      (the migration will fail to run)\n")
		}
	}

	rolled, err := sqlmigrate.Down(ctx, runner, migrations, n)
	if err != nil {
		return err
	}
	_ = rolled

	fmt.Println("cat", filepathUnclean(runner.LogPath))

	showFixes(fixedUp, fixedDown)
	return nil
}

func cmdStatus(ctx context.Context, state *State, runner *shmigrate.Migrator, migrations []sqlmigrate.Script) error {
	status, err := sqlmigrate.GetStatus(ctx, runner, migrations)
	if err != nil {
		return err
	}

	fmt.Fprintf(os.Stderr, "migrations_dir: %s\n", filepathUnclean(state.MigrationsDir))
	fmt.Fprintf(os.Stderr, "migrations_log: %s\n", filepathUnclean(state.LogPath))
	fmt.Fprintf(os.Stderr, "sql_command: %s\n", state.SQLCommand)
	fmt.Fprintf(os.Stderr, "\n")

	// show applied in reverse (most recent first)
	appliedList := make([]sqlmigrate.Migration, len(status.Applied))
	copy(appliedList, status.Applied)
	slices.Reverse(appliedList)

	fmt.Printf("# previous: %d\n", len(appliedList))
	for _, mig := range appliedList {
		fmt.Printf("   %s\n", mig.Name)
	}
	if len(appliedList) == 0 {
		fmt.Println("   # (no previous migrations)")
	}
	fmt.Println("")
	fmt.Printf("# pending: %d\n", len(status.Pending))
	for _, mig := range status.Pending {
		fmt.Printf("   %s\n", mig.Name)
	}
	if len(status.Pending) == 0 {
		fmt.Println("   # (no pending migrations)")
	}
	return nil
}
