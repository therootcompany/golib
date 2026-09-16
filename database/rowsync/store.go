// Package rowsync defines common row storage adapter interfaces and types.
//
// Every durable collection flows through one pipeline: fetch source and
// destination rows, build one rowsync.Plan with a rowsync.Planner, then apply
// that plan to a destination. Destinations never recompute changes: they
// apply Plan.Actions (complete rows in Before/After) and, for PostgreSQL,
// commit base-table and log changes in one transaction.
package rowsync

import "context"

// Message is an informational message returned during Init.
type Message struct {
	String string `json:"string"`
	Type   string `json:"type"`
}

// Fetcher reads records from a source.
type Fetcher[T any] interface {
	Init(context.Context) ([]Message, error)
	Fetch(context.Context) ([]T, error)
}

// InvalidReporter reports the count of invalid rows in a source.
type InvalidReporter interface {
	InvalidCount() int
}

// InvalidRowReporter reports the row numbers of invalid rows in a source.
type InvalidRowReporter interface {
	InvalidRows() []int
}

// Updater reads and writes records to a destination. Update applies a plan
// built elsewhere; it must not recompute changes or refetch rows it already
// has (Plan.Before carries the complete previous rows for deletes).
type Updater[T any] interface {
	Fetcher[T]
	Update(context.Context, Plan[T]) error
}

// Merge combines a partial source with existing state. Merged pipelines are
// insert-update only: destination rows the source lacks survive.
type Merge[T any] func(previous, current []T) ([]T, error)

// Result reports the outcome of a fetch → plan → apply run.
type Result[T any] struct {
	Source      []T
	Plan        Plan[T]
	Invalid     int
	InvalidRows []int
}
