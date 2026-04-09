package main

import (
	"context"
	"database/sql"
	"embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/joho/godotenv"
	_ "github.com/microsoft/go-mssqldb"

	"github.com/therootcompany/golib/database/sqlmigrate"
	"github.com/therootcompany/golib/database/sqlmigrate/msmigrate"
)

const version = "0.1.0"

//go:embed sql/migrations/*.sql
var migrationsFS embed.FS

func main() {
	_ = godotenv.Load()

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			fmt.Fprintln(os.Stdout, "")
			printUsage(os.Stdout)
			os.Exit(0)
		}
	}

	fs := flag.NewFlagSet("ms-todos", flag.ContinueOnError)
	fs.Usage = func() { printUsage(os.Stderr) }
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}

	args := fs.Args()
	if len(args) == 0 {
		printVersion(os.Stdout)
		fmt.Fprintln(os.Stdout, "")
		printUsage(os.Stdout)
		os.Exit(0)
	}

	ctx := context.Background()

	msURL := os.Getenv("MS_URL")
	if msURL == "" {
		fmt.Fprintf(os.Stderr, "Error: MS_URL environment variable is required\n")
		os.Exit(1)
	}

	db, err := sql.Open("sqlserver", msURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = db.Close() }()

	// migrations require a single connection, not a pool
	conn, err := db.Conn(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: acquiring connection for migrations: %v\n", err)
		os.Exit(1)
	}
	defer func() { _ = conn.Close() }()

	migrations := mustCollectMigrations()
	runner := msmigrate.New(conn)

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "migrate":
		err = runMigrate(ctx, runner, migrations, subArgs)
	case "add":
		autoMigrate(ctx, runner, migrations)
		err = runAdd(ctx, db, subArgs)
	case "list":
		autoMigrate(ctx, runner, migrations)
		err = runList(ctx, db, subArgs)
	case "done":
		autoMigrate(ctx, runner, migrations)
		err = runDone(ctx, db, subArgs)
	case "rm":
		autoMigrate(ctx, runner, migrations)
		err = runRm(ctx, db, subArgs)
	case "seed":
		autoMigrate(ctx, runner, migrations)
		err = runSeed(ctx, db)
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n\n", subcmd)
		printUsage(os.Stderr)
		os.Exit(1)
	}

	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}

func mustCollectMigrations() []sqlmigrate.Script {
	migrations, err := sqlmigrate.Collect(migrationsFS, "sql/migrations")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: collecting migrations: %v\n", err)
		os.Exit(1)
	}
	return migrations
}

func autoMigrate(ctx context.Context, runner sqlmigrate.Migrator, migrations []sqlmigrate.Script) {
	if _, err := sqlmigrate.Latest(ctx, runner, migrations); err != nil {
		fmt.Fprintf(os.Stderr, "Error: auto-migrate: %v\n", err)
		os.Exit(1)
	}
}

func printVersion(w *os.File) {
	fmt.Fprintf(w, "ms-todos v%s\n", version)
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, `USAGE
   ms-todos <command> [args]

COMMANDS
   migrate up [n]      apply pending migrations (all by default)
   migrate down [n]    roll back migrations (1 by default)
   migrate status      show applied and pending migrations
   migrate reset       drop all tables (rollback all migrations)

   seed                insert deterministic test data (idempotent)

   add <title>         create a new todo
   list                list todos
   done <id>           mark a todo as done
   rm <id>             delete a todo

ENVIRONMENT
   MS_URL              SQL Server connection string (loaded from .env)`)
}

func runMigrate(ctx context.Context, runner sqlmigrate.Migrator, migrations []sqlmigrate.Script, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("migrate requires a subcommand: up, down, status, or reset")
	}

	switch args[0] {
	case "up":
		n := -1
		if len(args) > 1 {
			var err error
			n, err = strconv.Atoi(args[1])
			if err != nil || n < 0 {
				return fmt.Errorf("%q is not a valid count", args[1])
			}
		}
		applied, err := sqlmigrate.Up(ctx, runner, migrations, n)
		if len(applied) == 0 && err == nil {
			fmt.Println("Already up-to-date.")
		} else if err == nil {
			fmt.Printf("Applied %d migration(s).\n", len(applied))
			for _, m := range applied {
				fmt.Printf("   %s\n", m.Name)
			}
		}
		return err

	case "down":
		n := 1
		if len(args) > 1 {
			var err error
			n, err = strconv.Atoi(args[1])
			if err != nil || n < 0 {
				return fmt.Errorf("%q is not a valid count", args[1])
			}
		}
		rolled, err := sqlmigrate.Down(ctx, runner, migrations, n)
		if len(rolled) == 0 && err == nil {
			fmt.Println("No migrations to roll back.")
		} else if err == nil {
			fmt.Printf("Rolled back %d migration(s).\n", len(rolled))
			for _, m := range rolled {
				fmt.Printf("   %s\n", m.Name)
			}
		}
		return err

	case "status":
		status, err := sqlmigrate.GetStatus(ctx, runner, migrations)
		if err != nil {
			return err
		}
		fmt.Printf("Applied: %d\n", len(status.Applied))
		for _, m := range status.Applied {
			fmt.Printf("   %s\n", m.Name)
		}
		fmt.Printf("\nPending: %d\n", len(status.Pending))
		for _, m := range status.Pending {
			fmt.Printf("   %s\n", m.Name)
		}
		return nil

	case "reset":
		rolled, err := sqlmigrate.Drop(ctx, runner, migrations)
		if len(rolled) == 0 && err == nil {
			fmt.Println("Nothing to reset.")
		} else if err == nil {
			fmt.Printf("Reset: rolled back %d migration(s).\n", len(rolled))
			for _, m := range rolled {
				fmt.Printf("   %s\n", m.Name)
			}
		}
		return err

	default:
		return fmt.Errorf("unknown migrate subcommand: %s (use up, down, status, or reset)", args[0])
	}
}
