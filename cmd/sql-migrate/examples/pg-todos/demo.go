package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/therootcompany/golib/cmd/sql-migrate/examples/pg-todos/internal/tododb"
)

func runAdd(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("add requires a title")
	}

	q := tododb.New(pool)

	// check if the last arg is a folder name
	var folderID string
	if len(args) >= 2 {
		candidate := strings.TrimSuffix(args[len(args)-1], "/")
		folder, err := q.FolderGetByName(ctx, candidate)
		if err == nil {
			folderID = folder.ID
			args = args[:len(args)-1]
		}
	}

	if len(args) == 0 {
		return fmt.Errorf("add requires a title")
	}
	title := strings.Join(args, " ")
	id := mustRandomHex(4)

	todo, err := q.TodoCreate(ctx, tododb.TodoCreateParams{
		ID:    id,
		Title: title,
	})
	if err != nil {
		return fmt.Errorf("creating todo: %w", err)
	}

	if folderID != "" {
		err = q.FolderAddTodo(ctx, tododb.FolderAddTodoParams{
			FolderID: folderID,
			TodoID:   todo.ID,
		})
		if err != nil {
			return fmt.Errorf("adding to folder: %w", err)
		}
	}

	fmt.Printf("Created: %s  %s\n", todo.ID, todo.Title)
	return nil
}

func runList(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	q := tododb.New(pool)

	if len(args) > 0 {
		name := strings.TrimSuffix(strings.Join(args, " "), "/")
		folder, err := q.FolderGetByName(ctx, name)
		if err != nil {
			return fmt.Errorf("folder %q: %w", name, err)
		}
		todos, err := q.FolderTodos(ctx, folder.ID)
		if err != nil {
			return fmt.Errorf("listing folder todos: %w", err)
		}
		if len(todos) == 0 {
			fmt.Printf("No todos in %s/\n", folder.Name)
			return nil
		}
		for _, t := range todos {
			printTodo(t.ID, t.Title, t.Status, t.CompletedAt, t.Priority)
		}
		return nil
	}

	todos, err := q.TodoListUnfoldered(ctx)
	if err != nil {
		return fmt.Errorf("listing todos: %w", err)
	}
	for _, t := range todos {
		printTodo(t.ID, t.Title, t.Status, t.CompletedAt, t.Priority)
	}

	folders, err := q.FolderList(ctx)
	if err != nil {
		return fmt.Errorf("listing folders: %w", err)
	}
	for _, f := range folders {
		fmt.Printf("  %s  %s/\n", f.ID, f.Name)
	}

	if len(todos) == 0 && len(folders) == 0 {
		fmt.Println("No todos.")
	}

	return nil
}

func printTodo(id, title, status string, completedAt pgtype.Timestamp, priority int32) {
	if completedAt.Valid {
		status = fmt.Sprintf("done %s", completedAt.Time.Format("2006-01-02"))
	}
	pri := ""
	if priority > 0 {
		pri = fmt.Sprintf(" [p%d]", priority)
	}
	fmt.Printf("  %s  %-10s %s%s\n", id, status, title, pri)
}

func runDone(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("done requires a todo ID")
	}

	q := tododb.New(pool)
	todo, err := q.TodoMarkDone(ctx, args[0])
	if err != nil {
		return fmt.Errorf("marking done: %w", err)
	}

	fmt.Printf("Done: %s  %s\n", todo.ID, todo.Title)
	return nil
}

func runRm(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("rm requires a todo ID")
	}

	q := tododb.New(pool)
	if err := q.TodoDelete(ctx, args[0]); err != nil {
		return fmt.Errorf("deleting todo: %w", err)
	}

	fmt.Printf("Deleted: %s\n", args[0])
	return nil
}

func runFolder(ctx context.Context, pool *pgxpool.Pool, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("folder requires a subcommand: create, list, add, rm, todos, delete")
	}

	q := tododb.New(pool)

	switch args[0] {
	case "create":
		if len(args) < 2 {
			return fmt.Errorf("folder create requires a name")
		}
		name := strings.Join(args[1:], " ")
		id := mustRandomHex(4)
		folder, err := q.FolderCreate(ctx, tododb.FolderCreateParams{
			ID:   id,
			Name: name,
		})
		if err != nil {
			return fmt.Errorf("creating folder: %w", err)
		}
		fmt.Printf("Created folder: %s  %s\n", folder.ID, folder.Name)

	case "list":
		folders, err := q.FolderList(ctx)
		if err != nil {
			return fmt.Errorf("listing folders: %w", err)
		}
		if len(folders) == 0 {
			fmt.Println("No folders.")
			return nil
		}
		for _, f := range folders {
			fmt.Printf("  %s  %s\n", f.ID, f.Name)
		}

	case "add":
		if len(args) < 3 {
			return fmt.Errorf("folder add requires <folder-id> <todo-id>")
		}
		err := q.FolderAddTodo(ctx, tododb.FolderAddTodoParams{
			FolderID: args[1],
			TodoID:   args[2],
		})
		if err != nil {
			return fmt.Errorf("adding todo to folder: %w", err)
		}
		fmt.Printf("Added todo %s to folder %s\n", args[2], args[1])

	case "rm":
		if len(args) < 3 {
			return fmt.Errorf("folder rm requires <folder-id> <todo-id>")
		}
		err := q.FolderRemoveTodo(ctx, tododb.FolderRemoveTodoParams{
			FolderID: args[1],
			TodoID:   args[2],
		})
		if err != nil {
			return fmt.Errorf("removing todo from folder: %w", err)
		}
		fmt.Printf("Removed todo %s from folder %s\n", args[2], args[1])

	case "todos":
		if len(args) < 2 {
			return fmt.Errorf("folder todos requires a folder ID")
		}
		todos, err := q.FolderTodos(ctx, args[1])
		if err != nil {
			return fmt.Errorf("listing folder todos: %w", err)
		}
		if len(todos) == 0 {
			fmt.Println("No todos in this folder.")
			return nil
		}
		for _, t := range todos {
			printTodo(t.ID, t.Title, t.Status, t.CompletedAt, t.Priority)
		}

	case "delete":
		if len(args) < 2 {
			return fmt.Errorf("folder delete requires a folder ID")
		}
		if err := q.FolderDelete(ctx, args[1]); err != nil {
			return fmt.Errorf("deleting folder: %w", err)
		}
		fmt.Printf("Deleted folder: %s\n", args[1])

	default:
		return fmt.Errorf("unknown folder subcommand: %s", args[0])
	}

	return nil
}

func mustRandomHex(n int) string {
	b := make([]byte, n)
	if _, err := rand.Read(b); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b)
}
