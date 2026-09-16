// Package pgdb provides a generic PostgreSQL database adapter.
// It can serve as both a source (Fetcher) and destination (Updater),
// enabling pipelines like gsheet -> pg or pg -> tsv.
//
// Store.DB accepts either *pgx.Conn (CLI, tests) or *pgxpool.Pool (servers).
// Import "github.com/jackc/pgx/v5/pgxpool" if using a pool.
package pgdb

import (
	"context"
	"fmt"
	"io/fs"
	"time"

	"github.com/therootcompany/golib/database/rowsync"

	"github.com/jackc/pgx/v5"
	"github.com/therootcompany/golib/database/sqlmigrate"
	"github.com/therootcompany/golib/database/sqlmigrate/pgmigrate"
)

// DBT is the minimum interface satisfied by both *pgx.Conn and *pgxpool.Pool.
type DBT interface {
	Ping(context.Context) error
	Begin(context.Context) (pgx.Tx, error)
}

// Connect establishes a single PostgreSQL connection with a 5-second timeout.
// For servers, prefer pgxpool.New and pass the pool as DBT.
func Connect(parent context.Context, pgURL string) (*pgx.Conn, error) {
	ctx, cancel := context.WithTimeout(parent, 5*time.Second)
	defer cancel()
	conn, err := pgx.Connect(ctx, pgURL)
	if err != nil {
		return nil, fmt.Errorf("connect PostgreSQL: %w", err)
	}
	return conn, nil
}

// Migrate runs pending migrations from an fs.FS on the connection.
// Returns messages about what was applied, or nil if nothing changed.
func Migrate(ctx context.Context, conn *pgx.Conn, migrationsFS fs.FS) ([]rowsync.Message, error) {
	ddls, err := sqlmigrate.Collect(migrationsFS, ".")
	if err != nil {
		return nil, fmt.Errorf("collect migrations: %w", err)
	}
	runner := pgmigrate.New(conn)
	applied, err := sqlmigrate.Latest(ctx, runner, ddls)
	if err != nil {
		return nil, fmt.Errorf("apply migrations: %w", err)
	}
	if len(applied) == 0 {
		return nil, nil
	}
	msgs := make([]rowsync.Message, 0, len(applied)+1)
	for _, m := range applied {
		msgs = append(msgs, rowsync.Message{String: m.Name, Type: "debug"})
	}
	msgs = append(msgs, rowsync.Message{
		String: fmt.Sprintf("applied %d migration(s)", len(applied)),
		Type:   "info",
	})
	return msgs, nil
}

// Store is a generic PostgreSQL Fetcher and Updater.
// The application provides FetchFunc, UpsertFunc, and optionally DeleteFunc
// to define the SQL.
// Capture the connection or pool in the function closures:
//
//	store := &dbpg.Store[MyRow]{
//	    DB: pool,
//	    FetchFunc: func(ctx context.Context) ([]MyRow, error) {
//	        return queries.MyRowList(ctx)
//	    },
//	    UpsertFunc: func(ctx context.Context, tx pgx.Tx, row MyRow) error {
//	        return queries.New(tx).MyRowUpsert(ctx, row)
//	    },
//	    DeleteFunc: func(ctx context.Context, tx pgx.Tx, row MyRow) error {
//	        return queries.New(tx).MyRowDelete(ctx, row.ID)
//	    },
//	}
type Store[T any] struct {
	DB         DBT
	Migrations fs.FS // optional; if set, Init runs migrations
	FetchFunc  func(ctx context.Context) ([]T, error)
	UpsertFunc func(ctx context.Context, tx pgx.Tx, row T) error
	DeleteFunc func(ctx context.Context, tx pgx.Tx, row T) error // required when a plan carries deletes
	Normalize  func([]T)
}

var _ rowsync.Fetcher[struct{}] = (*Store[struct{}])(nil)
var _ rowsync.Updater[struct{}] = (*Store[struct{}])(nil)

// Init pings the connection and optionally runs migrations.
func (s *Store[T]) Init(ctx context.Context) ([]rowsync.Message, error) {
	if s == nil || s.DB == nil {
		return nil, fmt.Errorf("PostgreSQL connection is required")
	}
	if err := s.DB.Ping(ctx); err != nil {
		return nil, err
	}
	if s.Migrations != nil {
		// Migrations require a *pgx.Conn (pgmigrate uses conn-specific APIs).
		conn, ok := s.DB.(*pgx.Conn)
		if !ok {
			return nil, fmt.Errorf("migrations require a *pgx.Conn, got %T", s.DB)
		}
		msgs, err := Migrate(ctx, conn, s.Migrations)
		if err != nil {
			return nil, err
		}
		for i := range msgs {
			msgs[i].Type = "info"
		}
		return msgs, nil
	}
	return []rowsync.Message{{String: "PostgreSQL", Type: "debug"}}, nil
}

// Fetch reads all rows from PostgreSQL using FetchFunc.
func (s *Store[T]) Fetch(ctx context.Context) ([]T, error) {
	if s == nil || s.DB == nil {
		return nil, fmt.Errorf("PostgreSQL connection is required")
	}
	if s.FetchFunc == nil {
		return nil, fmt.Errorf("FetchFunc is required")
	}
	rows, err := s.FetchFunc(ctx)
	if err != nil {
		return nil, err
	}
	if s.Normalize != nil {
		s.Normalize(rows)
	}
	return rows, nil
}

// Update applies a plan within one transaction: insert and update actions
// upsert Action.After, delete actions pass Action.Before to DeleteFunc.
func (s *Store[T]) Update(ctx context.Context, plan rowsync.Plan[T]) error {
	if s == nil || s.DB == nil {
		return fmt.Errorf("PostgreSQL connection is required")
	}
	if s.UpsertFunc == nil {
		return fmt.Errorf("UpsertFunc is required")
	}
	if len(plan.Actions) == 0 {
		return nil
	}
	tx, err := s.DB.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	for _, action := range plan.Actions {
		switch action.Kind {
		case rowsync.InsertAction, rowsync.UpdateAction:
			if err := s.UpsertFunc(ctx, tx, *action.After); err != nil {
				return err
			}
		case rowsync.DeleteAction:
			if s.DeleteFunc == nil {
				return fmt.Errorf("DeleteFunc is required for delete actions")
			}
			if err := s.DeleteFunc(ctx, tx, *action.Before); err != nil {
				return err
			}
		}
	}
	return tx.Commit(ctx)
}
