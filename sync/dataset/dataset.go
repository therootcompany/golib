// Package dataset manages values that are periodically re-fetched from an
// upstream source and hot-swapped behind atomic pointers. Consumers read via
// View.Value (lock-free); a single Load drives any number of views off one
// Fetcher, so shared sources (one git pull, one zip download) don't get
// re-fetched per view.
//
// Typical lifecycle:
//
//	g := dataset.NewGroup(repo) // *gitshallow.Repo satisfies Fetcher
//	inbound  := dataset.Add(g, func() (*ipcohort.Cohort, error) { ... })
//	outbound := dataset.Add(g, func() (*ipcohort.Cohort, error) { ... })
//	if err := g.Load(ctx); err != nil { ... }        // initial populate
//	go g.Tick(ctx, 47*time.Minute)                   // background refresh
//	current := inbound.Value()                        // lock-free read
package dataset

import (
	"context"
	"sync/atomic"
	"time"
)

// Fetcher reports whether an upstream source has changed since the last call.
// Implementations should dedup rapid-fire calls internally (e.g. gitshallow
// skips redundant pulls within a short window; httpcache uses ETag).
type Fetcher interface {
	Fetch() (updated bool, err error)
}

// FetcherFunc adapts a plain function to Fetcher.
type FetcherFunc func() (bool, error)

func (f FetcherFunc) Fetch() (bool, error) { return f() }

// NopFetcher always reports no update. Use for groups backed by local files
// that don't need a refresh cycle.
type NopFetcher struct{}

func (NopFetcher) Fetch() (bool, error) { return false, nil }

// Group ties one Fetcher to one or more views. A Load call fetches once and,
// on the first call or when the source reports a change, reloads every view
// and atomically swaps its current value.
type Group struct {
	fetcher Fetcher
	views   []reloader
	loaded  atomic.Bool
}

// reloader is a type-erased handle to a View's reload function.
type reloader interface {
	reload() error
}

// NewGroup creates a Group backed by fetcher.
func NewGroup(fetcher Fetcher) *Group {
	return &Group{fetcher: fetcher}
}

// Load fetches upstream and, on the first call or whenever the fetcher reports
// a change, reloads every view and atomically installs the new values.
func (g *Group) Load(ctx context.Context) error {
	updated, err := g.fetcher.Fetch()
	if err != nil {
		return err
	}
	if g.loaded.Load() && !updated {
		return nil
	}
	for _, v := range g.views {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := v.reload(); err != nil {
			return err
		}
	}
	g.loaded.Store(true)
	return nil
}

// Tick calls Load every interval until ctx is done. Load errors are passed to
// onError (if non-nil) and do not stop the loop; callers choose whether to log,
// count, page, or ignore. Run in a goroutine: `go g.Tick(ctx, d, onError)`.
func (g *Group) Tick(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := g.Load(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// View is a read-only handle to one dataset inside a Group.
type View[T any] struct {
	loader func() (*T, error)
	ptr    atomic.Pointer[T]
}

// Value returns the current snapshot. Nil before the Group is first loaded.
func (v *View[T]) Value() *T {
	return v.ptr.Load()
}

func (v *View[T]) reload() error {
	t, err := v.loader()
	if err != nil {
		return err
	}
	v.ptr.Store(t)
	return nil
}

// Add registers a new view in g and returns it. Call after NewGroup and
// before the first Load.
func Add[T any](g *Group, loader func() (*T, error)) *View[T] {
	v := &View[T]{loader: loader}
	g.views = append(g.views, v)
	return v
}
