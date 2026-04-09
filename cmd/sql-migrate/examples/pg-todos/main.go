package main

import (
	"context"
	"embed"
	"errors"
	"flag"
	"fmt"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"

	"github.com/therootcompany/golib/database/sqlmigrate"
	"github.com/therootcompany/golib/database/sqlmigrate/pgmigrate"
)

const version = "0.1.0"

//go:generate sqlc generate

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

	fs := flag.NewFlagSet("pg-todos", flag.ContinueOnError)
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

	pgURL := os.Getenv("PG_URL")
	if pgURL == "" {
		fmt.Fprintf(os.Stderr, "Error: PG_URL environment variable is required\n")
		os.Exit(1)
	}

	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: connecting to database: %v\n", err)
		os.Exit(1)
	}
	defer pool.Close()

	migrations := mustCollectMigrations()
	runner := pgmigrate.New(pool)

	subcmd := args[0]
	subArgs := args[1:]

	switch subcmd {
	case "migrate":
		err = runMigrate(ctx, runner, migrations, subArgs)
	case "add":
		autoMigrate(ctx, runner, migrations)
		err = runAdd(ctx, pool, subArgs)
	case "list":
		autoMigrate(ctx, runner, migrations)
		err = runList(ctx, pool, subArgs)
	case "done":
		autoMigrate(ctx, runner, migrations)
		err = runDone(ctx, pool, subArgs)
	case "rm":
		autoMigrate(ctx, runner, migrations)
		err = runRm(ctx, pool, subArgs)
	case "seed":
		autoMigrate(ctx, runner, migrations)
		err = runSeed(ctx, pool)
	case "folder":
		autoMigrate(ctx, runner, migrations)
		err = runFolder(ctx, pool, subArgs)
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
	fmt.Fprintf(w, "pg-todos v%s\n", version)
}

func printUsage(w *os.File) {
	fmt.Fprintln(w, `USAGE
   pg-todos <command> [args]

COMMANDS
   migrate up [n]      apply pending migrations (all by default)
   migrate down [n]    roll back migrations (1 by default)
   migrate status      show applied and pending migrations
   migrate reset       drop all tables (rollback all migrations)

   seed                insert deterministic test data (idempotent)

   add <title> [folder] create a new todo (optionally in a folder)
   list [folder-name]  list todos (in a folder, or root + folders)
   done <id>           mark a todo as done
   rm <id>             delete a todo

   folder create <name>              create a folder
   folder list                       list all folders
   folder add <folder-id> <todo-id>  assign a todo to a folder
   folder rm <folder-id> <todo-id>   remove a todo from a folder
   folder todos <folder-id>          list todos in a folder
   folder delete <folder-id>         delete a folder

ENVIRONMENT
   PG_URL              PostgreSQL connection string (loaded from .env)`)
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
