// Command todos demonstrates pgmigrate with embedded SQL migrations.
//
// Usage:
//
//	export PG_URL='postgres://user:pass@localhost:5432/dbname?sslmode=require'
//	go run . up        # apply all pending migrations
//	go run . up 1      # apply next 1 migration
//	go run . down      # roll back last migration
//	go run . down 2    # roll back last 2 migrations
//	go run . status    # show applied and pending
//	go run . reset     # roll back all migrations
package main

import (
	"context"
	"embed"
	"fmt"
	stdfs "io/fs"
	"os"
	"strconv"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/therootcompany/golib/database/sqlmigrate"
	"github.com/therootcompany/golib/database/sqlmigrate/pgmigrate"
)

//go:embed migrations/*.sql
var migrationsFS embed.FS

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
}

func run() error {
	ctx := context.Background()

	pgURL := os.Getenv("PG_URL")
	if pgURL == "" {
		return fmt.Errorf("PG_URL environment variable is required")
	}

	pool, err := pgxpool.New(ctx, pgURL)
	if err != nil {
		return fmt.Errorf("connecting: %w", err)
	}
	defer pool.Close()

	subFS, err := stdfs.Sub(migrationsFS, "migrations")
	if err != nil {
		return fmt.Errorf("reading migrations: %w", err)
	}
	migrations, err := sqlmigrate.Collect(subFS)
	if err != nil {
		return fmt.Errorf("collecting migrations: %w", err)
	}

	runner := pgmigrate.New(pool)

	args := os.Args[1:]
	if len(args) == 0 {
		args = []string{"status"}
	}

	switch args[0] {
	case "up":
		n := -1
		if len(args) > 1 {
			n, err = strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("up count must be a positive integer")
			}
		}
		applied, err := sqlmigrate.Up(ctx, runner, migrations, n)
		if err != nil {
			return err
		}
		if len(applied) == 0 {
			fmt.Println("Already up-to-date.")
		} else {
			for _, name := range applied {
				fmt.Printf("  applied: %s\n", name)
			}
		}

	case "down":
		n := 1
		if len(args) > 1 {
			n, err = strconv.Atoi(args[1])
			if err != nil || n < 1 {
				return fmt.Errorf("down count must be a positive integer")
			}
		}
		rolled, err := sqlmigrate.Down(ctx, runner, migrations, n)
		if err != nil {
			return err
		}
		if len(rolled) == 0 {
			fmt.Println("Nothing to roll back.")
		} else {
			for _, name := range rolled {
				fmt.Printf("  rolled back: %s\n", name)
			}
		}

	case "status":
		status, err := sqlmigrate.GetStatus(ctx, runner, migrations)
		if err != nil {
			return err
		}
		fmt.Printf("Applied: %d\n", len(status.Applied))
		for _, name := range status.Applied {
			fmt.Printf("  %s\n", name)
		}
		fmt.Printf("Pending: %d\n", len(status.Pending))
		for _, name := range status.Pending {
			fmt.Printf("  %s\n", name)
		}

	case "reset":
		rolled, err := sqlmigrate.Down(ctx, runner, migrations, -1)
		if err != nil {
			return err
		}
		if len(rolled) == 0 {
			fmt.Println("Nothing to reset.")
		} else {
			for _, name := range rolled {
				fmt.Printf("  rolled back: %s\n", name)
			}
		}

	default:
		return fmt.Errorf("unknown command %q (use: up, down, status, reset)", args[0])
	}

	return nil
}
