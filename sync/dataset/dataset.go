// Package dataset manages values that are periodically re-fetched from an
// upstream source and hot-swapped behind atomic pointers. Consumers read via
// View.Value (lock-free); a single Load drives any number of views off a
// shared set of Fetchers, so upstreams (one git pull, one tar.gz download)
// don't get re-fetched per view.
//
// Typical lifecycle:
//
//	s := dataset.NewSet(repo) // *gitshallow.Repo satisfies Fetcher
//	inbound  := dataset.Add(s, func(ctx context.Context) (*ipcohort.Cohort, error) { ... })
//	outbound := dataset.Add(s, func(ctx context.Context) (*ipcohort.Cohort, error) { ... })
//	if err := s.Load(ctx); err != nil { ... }       // initial populate
//	go s.Tick(ctx, 47*time.Minute, onError)         // background refresh
//	current := inbound.Value()                      // lock-free read
package dataset

import (
	"context"
	"errors"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// Fetcher reports whether an upstream source has changed since the last call.
// Implementations should dedup rapid-fire calls internally (e.g. gitshallow
// skips redundant pulls within a short window; httpcache uses ETag) and must
// honor ctx so Set.Tick can cancel mid-fetch on shutdown.
type Fetcher interface {
	Fetch(ctx context.Context) (updated bool, err error)
}

// FetcherFunc adapts a plain function to Fetcher.
type FetcherFunc func(ctx context.Context) (bool, error)

func (f FetcherFunc) Fetch(ctx context.Context) (bool, error) { return f(ctx) }

// NopFetcher always reports no update. Use for sets whose source never
// changes (test fixtures, embedded data).
type NopFetcher struct{}

func (NopFetcher) Fetch(ctx context.Context) (bool, error) { return false, nil }

// PollFiles returns a Fetcher that stat's the given paths and reports
// "updated" whenever any file's size or modtime has changed since the last
// call. The first call always reports updated=true.
//
// Use for Sets whose source is local files that may be edited out of band
// (e.g. a user-provided --inbound list) — pair with Set.Tick to pick up
// changes automatically.
func PollFiles(paths ...string) Fetcher {
	return &filePoller{paths: paths, stats: make(map[string]fileStat, len(paths))}
}

type fileStat struct {
	size    int64
	modTime time.Time
}

type filePoller struct {
	mu    sync.Mutex
	paths []string
	stats map[string]fileStat
}

func (p *filePoller) Fetch(ctx context.Context) (bool, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	changed := false
	for _, path := range p.paths {
		if err := ctx.Err(); err != nil {
			return false, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return false, err
		}
		cur := fileStat{size: info.Size(), modTime: info.ModTime()}
		if prev, ok := p.stats[path]; !ok || prev != cur {
			changed = true
			p.stats[path] = cur
		}
	}
	return changed, nil
}

// Set ties one or more Fetchers to one or more views. A Load call fetches
// each source and, on the first call or when any source reports a change,
// reloads every view and atomically swaps its current value. Use multiple
// fetchers when a single logical dataset is spread across several archives
// (e.g. GeoLite2 City + ASN); a single fetcher is the common case (one git
// repo, one tar.gz).
// Set serializes Load and Close with a mutex so concurrent callers (e.g. an
// /admin/reload handler firing while Tick also fires) don't race the views.
// Add and AddInitial mutate s.views without locking — they MUST be called
// before the first Load.
type Set struct {
	mu       sync.Mutex
	fetchers []Fetcher
	views    []reloader
	loaded   atomic.Bool
}

// reloader is a type-erased handle to a View's reload function.
type reloader interface {
	reload(ctx context.Context) error
}

// NewSet creates a Set backed by fetchers. All fetchers are called on every
// Load; the set reloads its views whenever any one of them reports a change.
func NewSet(fetchers ...Fetcher) *Set {
	return &Set{fetchers: fetchers}
}

// Loaded reports whether Load has completed successfully at least once.
func (s *Set) Loaded() bool {
	return s.loaded.Load()
}

// Load fetches upstream and, on the first call or whenever any fetcher
// reports a change, reloads every view and atomically installs the new values.
func (s *Set) Load(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	updated := false
	for _, f := range s.fetchers {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := f.Fetch(ctx)
		if err != nil {
			return err
		}
		if u {
			updated = true
		}
	}
	if s.loaded.Load() && !updated {
		return nil
	}
	for _, v := range s.views {
		if err := ctx.Err(); err != nil {
			return err
		}
		if err := v.reload(ctx); err != nil {
			return err
		}
	}
	s.loaded.Store(true)
	return nil
}

// Close closes every view's currently-held value. Call on shutdown to
// release any OS resources held by the final snapshots (file handles,
// network connections). Safe to call on a Set that hasn't been loaded
// or whose views hold pure in-memory values — non-Closer values are
// skipped. Returns joined errors from any Close failures.
//
// Callers MUST cancel the ctx passed to Tick (and let Tick return)
// before calling Close, or a refresh after Close can reanimate views.
func (s *Set) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	var errs []error
	for _, v := range s.views {
		if c, ok := v.(io.Closer); ok {
			if err := c.Close(); err != nil {
				errs = append(errs, err)
			}
		}
	}
	return errors.Join(errs...)
}

// Tick calls Load every interval until ctx is done. Load errors are passed to
// onError (if non-nil) and do not stop the loop; callers choose whether to log,
// count, page, or ignore. Run in a goroutine: `go s.Tick(ctx, d, onError)`.
func (s *Set) Tick(ctx context.Context, interval time.Duration, onError func(error)) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := s.Load(ctx); err != nil && onError != nil {
				onError(err)
			}
		}
	}
}

// View is a read-only handle to one dataset inside a Set.
type View[T any] struct {
	loader   func(ctx context.Context) (*T, error)
	ptr      atomic.Pointer[T]
	loadedAt atomic.Pointer[time.Time] // nil until first successful reload
}

// Value returns the current snapshot. Nil before the Set is first loaded
// unless the view was registered via AddInitial.
func (v *View[T]) Value() *T {
	return v.ptr.Load()
}

// LoadedAt returns the time of the most recent successful reload, or the
// zero time if the view has never loaded.
func (v *View[T]) LoadedAt() time.Time {
	if t := v.loadedAt.Load(); t != nil {
		return *t
	}
	return time.Time{}
}

// Close clears the view and closes the currently-held value if it
// implements io.Closer. Idempotent — subsequent calls are no-ops.
func (v *View[T]) Close() error {
	prev := v.ptr.Swap(nil)
	if prev == nil {
		return nil
	}
	if closer, ok := any(prev).(io.Closer); ok {
		return closer.Close()
	}
	return nil
}

func (v *View[T]) reload(ctx context.Context) error {
	t, err := v.loader(ctx)
	if err != nil {
		return err
	}
	prev := v.ptr.Swap(t)
	// Close the replaced value if it holds OS resources (open file handles,
	// network connections). Geoip readers and similar wrappers implement
	// io.Closer; cohort and other pure-in-memory values don't — the type
	// assertion filters to only the ones that need it. The `prev != nil`
	// guard is required because any(typedNilPtr) is a non-nil interface
	// wrapping a nil pointer — the type assertion succeeds and we'd
	// call Close on a nil receiver.
	if prev != nil {
		if closer, ok := any(prev).(io.Closer); ok {
			_ = closer.Close()
		}
	}
	now := time.Now()
	v.loadedAt.Store(&now)
	return nil
}

// Add registers a new view in s and returns it. Call after NewSet and before
// the first Load. View.Value() returns nil until Set.Load succeeds.
// The loader receives the ctx passed to Set.Load, so long-running parses
// should honor ctx.Err() to support graceful shutdown.
func Add[T any](s *Set, loader func(ctx context.Context) (*T, error)) *View[T] {
	v := &View[T]{loader: loader}
	s.views = append(s.views, v)
	return v
}

// AddInitial is like Add but pre-populates the view with initial, so
// View.Value() returns a usable (possibly empty) value before the first
// Load completes. Use when the initial state is benign (e.g. an empty
// cohort matches nothing) and you want to start serving before the
// first load finishes.
func AddInitial[T any](s *Set, initial *T, loader func(ctx context.Context) (*T, error)) *View[T] {
	v := &View[T]{loader: loader}
	v.ptr.Store(initial)
	s.views = append(s.views, v)
	return v
}
