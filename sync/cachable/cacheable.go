// Package cachable defines contracts for lazily refreshed cached values.
package cachable

import (
	"context"
	"time"
)

// Status describes the currently published snapshot. StaleAt is the next
// time the implementation wants a freshness check; it is not necessarily
// the time at which the value becomes unusable.
type Status struct {
	LoadedAt   time.Time
	StaleAt    time.Time
	Refreshing bool
	HasValue   bool
	LastError  error
}

// Cacheable is a refreshable, atomically published snapshot. Load always
// waits for the first snapshot. For later loads, wait controls whether the
// caller waits for a due or in-flight refresh.
type Cacheable[T any] interface {
	Load(ctx context.Context, wait bool) (*T, error)
	Current() *T
	Due(ctx context.Context) (due bool, err error)
	Revalidate(ctx context.Context) (started bool, err error)
	Clear() error
}

// Mutable is the optional manual publication capability.
type Mutable[T any] interface {
	Set(*T) error
	Clear() error
}

// Inspectable is the optional status capability.
type Inspectable interface {
	Status() Status
}

// Tickable is the optional background revalidation lifecycle.
type Tickable interface {
	Start(ctx context.Context, interval time.Duration)
	Stop() error
}
