package main

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"fmt"
	"strings"
)

func runAdd(ctx context.Context, db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("add requires a title")
	}

	title := strings.Join(args, " ")
	id := mustRandomHex(4)

	_, err := db.ExecContext(
		ctx,
		"INSERT INTO todos (id, title) VALUES (?, ?)",
		id,
		title,
	)
	if err != nil {
		return fmt.Errorf("creating todo: %w", err)
	}

	fmt.Printf("Created: %s  %s\n", id, title)
	return nil
}

func runList(ctx context.Context, db *sql.DB, args []string) error {
	rows, err := db.QueryContext(
		ctx,
		"SELECT id, title, status, completed_at, priority FROM todos ORDER BY created_at",
	)
	if err != nil {
		return fmt.Errorf("listing todos: %w", err)
	}
	defer func() { _ = rows.Close() }()

	count := 0
	for rows.Next() {
		var (
			id          string
			title       string
			status      string
			completedAt sql.NullTime
			priority    int32
		)
		if err := rows.Scan(&id, &title, &status, &completedAt, &priority); err != nil {
			return fmt.Errorf("scanning todo: %w", err)
		}

		displayStatus := status
		if completedAt.Valid {
			displayStatus = fmt.Sprintf("done %s", completedAt.Time.Format("2006-01-02"))
		}
		pri := ""
		if priority > 0 {
			pri = fmt.Sprintf(" [p%d]", priority)
		}
		fmt.Printf("  %s  %-10s %s%s\n", id, displayStatus, title, pri)
		count++
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("reading todos: %w", err)
	}

	if count == 0 {
		fmt.Println("No todos.")
	}

	return nil
}

func runDone(ctx context.Context, db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("done requires a todo ID")
	}

	result, err := db.ExecContext(
		ctx,
		"UPDATE todos SET status = 'done', completed_at = NOW() WHERE id = ?",
		args[0],
	)
	if err != nil {
		return fmt.Errorf("marking done: %w", err)
	}

	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("todo %q not found", args[0])
	}

	fmt.Printf("Done: %s\n", args[0])
	return nil
}

func runRm(ctx context.Context, db *sql.DB, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("rm requires a todo ID")
	}

	result, err := db.ExecContext(
		ctx,
		"DELETE FROM todos WHERE id = ?",
		args[0],
	)
	if err != nil {
		return fmt.Errorf("deleting todo: %w", err)
	}

	n, _ := result.RowsAffected()
	if n == 0 {
		return fmt.Errorf("todo %q not found", args[0])
	}

	fmt.Printf("Deleted: %s\n", args[0])
	return nil
}

func runSeed(ctx context.Context, db *sql.DB) error {
	type seedTodo struct {
		ID    string
		Title string
	}

	todos := []seedTodo{
		{ID: "seed0010", Title: "Review Q2 financial reports"},
		{ID: "seed0011", Title: "Update SSL certificates"},
		{ID: "seed0020", Title: "Deploy v2.3.1 to staging"},
		{ID: "seed0021", Title: "Rotate API keys"},
		{ID: "seed0022", Title: "Audit access logs"},
	}

	for _, t := range todos {
		_, err := db.ExecContext(
			ctx,
			"INSERT IGNORE INTO todos (id, title) VALUES (?, ?)",
			t.ID,
			t.Title,
		)
		if err != nil {
			return fmt.Errorf("seeding todo %q: %w", t.Title, err)
		}
		fmt.Printf("  Todo:   %s  %s\n", t.ID, t.Title)
	}

	// Mark two as done
	for _, id := range []string{"seed0010", "seed0011"} {
		_, err := db.ExecContext(
			ctx,
			"UPDATE todos SET status = 'done', completed_at = NOW() WHERE id = ? AND status != 'done'",
			id,
		)
		if err != nil {
			return fmt.Errorf("seeding mark done %s: %w", id, err)
		}
	}

	fmt.Println("Seed complete.")
	return nil
}

func mustRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
