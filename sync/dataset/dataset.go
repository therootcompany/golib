// Package dataset manages values that are periodically re-fetched from an
// upstream source and hot-swapped behind atomic pointers. Consumers read via
// View.Value (lock-free); a single Load drives any number of views off a
// shared set of Upstreams, so upstreams (one git pull, one tar.gz download)
// don't get re-fetched per view.
//
// Typical lifecycle:
//
//	s := dataset.NewSet(repo) // *gitshallow.Repo satisfies Upstream
//	inbound  := dataset.Add(s, func(ctx context.Context) (*ipcohort.Cohort, error) { ... })
//	outbound := dataset.Add(s, func(ctx context.Context) (*ipcohort.Cohort, error) { ... })
//	if err := s.Load(ctx, true); err != nil { ... }       // initial populate
//	inbound.Start(ctx, 47*time.Minute)              // optional refresh
//	current := inbound.Current()                    // lock-free read
package dataset

import (
	"context"
	"io"
	"os"
	"sync"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/sync/cachable"
)

// Upstream reports whether an upstream source has changed since the last call.
// Implementations should dedup rapid-fire calls internally (e.g. gitshallow
// skips redundant pulls within a short window; httpcache uses ETag) and must
// honor ctx so asynchronous updates can cancel on shutdown.
type Upstream interface {
	Update(ctx context.Context) (updated bool, err error)
}

// UpstreamFunc adapts a plain function to Upstream.
type UpstreamFunc func(ctx context.Context) (bool, error)

func (f UpstreamFunc) Update(ctx context.Context) (bool, error) { return f(ctx) }

// NopUpstream always reports no update. Use for sets whose source never
// changes (test fixtures, embedded data).
type NopUpstream struct{}

func (NopUpstream) Update(ctx context.Context) (bool, error) { return false, nil }

// PollFiles returns a Upstream that stat's the given paths and reports
// "updated" whenever any file's size or modtime has changed since the last
// call. The first call always reports updated=true.
//
// Use for Sets whose source is local files that may be edited out of band
// (e.g. a user-provided --inbound list) — pair with Set.Start to pick up
// changes automatically.
func PollFiles(paths ...string) Upstream {
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

func (p *filePoller) Update(ctx context.Context) (bool, error) {
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

// Set ties one or more Upstreams to one or more views. A Load call fetches
// each source and, on the first call or when any source reports a change,
// reloads every view and atomically swaps its current value. Use multiple
// fetchers when a single logical dataset is spread across several archives
// (e.g. GeoLite2 City + ASN); a single fetcher is the common case (one git
// repo, one tar.gz).
// Set serializes snapshot publication so concurrent callers do not race views.
// Add and AddInitial mutate s.views without locking — they MUST be called
// before the first Load.
type Set struct {
	publishMu      sync.Mutex
	fetchers       []Upstream
	views          []reloader
	loaded         atomic.Bool
	loadedAt       atomic.Pointer[time.Time]
	start          sync.Once
	cancel         context.CancelFunc
	refresh        cachable.Refresh
	generation     atomic.Uint64
	RefreshTimeout time.Duration
	// RefreshInterval gates how often Revalidate will start a refresh. Zero
	// means always due (freshness is delegated to the upstreams' own dedup
	// windows). Set to a positive duration to match the other cachable
	// implementations' time-based Due.
	RefreshInterval time.Duration
}

// reloader is a type-erased handle to a View's reload function.
type reloader interface {
	prepare(ctx context.Context) (any, error)
	publish(value any)
	clear()
}

// NewSet creates a Set backed by fetchers. All fetchers are called on every
// Load; the set reloads its views whenever any one of them reports a change.
func NewSet(fetchers ...Upstream) *Set {
	return &Set{fetchers: fetchers}
}

// Loaded reports whether Load has completed successfully at least once.
func (s *Set) Loaded() bool {
	return s.loaded.Load()
}

// Due reports whether the set should be revalidated. With RefreshInterval > 0
// it returns false until StaleAt (loadedAt + RefreshInterval) has passed, so a
// hot path calling Load(false) does not start a refresh on every request.
// With RefreshInterval == 0 it always returns true: the upstreams own their
// own dedup windows (httpcache ETag, gitshallow pull throttling) and a refresh
// is a cheap "nothing changed" check.
func (s *Set) Due(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if s.RefreshInterval <= 0 {
		return true, nil
	}
	if !s.loaded.Load() {
		return true, nil
	}
	loadedAt := s.loadedAt.Load()
	if loadedAt == nil {
		return true, nil
	}
	return !time.Now().Before(loadedAt.Add(s.RefreshInterval)), nil
}

// Revalidate checks whether work is due and starts one asynchronous update.
// Concurrent calls coalesce onto the same update. The update runs with a
// detached context bounded by RefreshTimeout (default 5 minutes) so a
// cancelled caller context does not kill background work.
func (s *Set) Revalidate(ctx context.Context) (started bool, err error) {
	due, err := s.Due(ctx)
	if err != nil || !due {
		return false, err
	}
	if !s.refresh.Begin() {
		return false, nil
	}
	go func() {
		timeout := s.RefreshTimeout
		if timeout <= 0 {
			timeout = 5 * time.Minute
		}
		refreshCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), timeout)
		defer cancel()
		s.refresh.Finish(s.update(refreshCtx))
	}()
	return true, nil
}

func (s *Set) update(ctx context.Context) error {
	generation := s.generation.Load()
	updated := false
	for _, f := range s.fetchers {
		if err := ctx.Err(); err != nil {
			return err
		}
		u, err := f.Update(ctx)
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
	prepared := make([]any, len(s.views))
	for i, v := range s.views {
		if err := ctx.Err(); err != nil {
			return err
		}
		value, err := v.prepare(ctx)
		if err != nil {
			return err
		}
		prepared[i] = value
	}
	s.publishMu.Lock()
	defer s.publishMu.Unlock()
	if s.generation.Load() != generation {
		return nil
	}
	for i, v := range s.views {
		v.publish(prepared[i])
	}
	now := time.Now()
	s.loadedAt.Store(&now)
	s.loaded.Store(true)
	return nil
}

// Load performs the initial load, or revalidates an already-loaded set. It
// keeps the last good snapshot when a later revalidation fails.
func (s *Set) Load(ctx context.Context, wait bool) error {
	_, err := s.Revalidate(ctx)
	if err != nil {
		return err
	}
	if !s.loaded.Load() || wait {
		return s.refresh.Wait(ctx)
	}
	return nil
}

// Start starts at most one optional background revalidation ticker.
func (s *Set) Start(ctx context.Context, interval time.Duration) {
	s.start.Do(func() {
		if interval <= 0 {
			interval = time.Hour
		}
		tickCtx, cancel := context.WithCancel(ctx)
		s.cancel = cancel
		go func() {
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-tickCtx.Done():
					return
				case <-ticker.C:
					_, _ = s.Revalidate(tickCtx)
				}
			}
		}()
	})
}

// Stop stops the optional background ticker and waits for any in-flight
// refresh to finish or reach RefreshTimeout. It does not clear snapshots.
func (s *Set) Stop() error {
	if s.cancel != nil {
		s.cancel()
	}
	timeout := s.RefreshTimeout
	if timeout <= 0 {
		timeout = 5 * time.Minute
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	return s.refresh.Stop(ctx)
}

// Clear removes every published view and closes values that own resources.
// The set remains usable and may be loaded again.
func (s *Set) Clear() error {
	s.generation.Add(1)
	s.loaded.Store(false)
	s.loadedAt.Store(nil)
	s.publishMu.Lock()
	defer s.publishMu.Unlock()
	for _, v := range s.views {
		v.clear()
	}
	return nil
}

// View is a read-only handle to one dataset inside a Set.
type View[T any] struct {
	set      *Set
	loader   func(ctx context.Context) (*T, error)
	ptr      atomic.Pointer[T]
	loadedAt atomic.Pointer[time.Time] // nil until first successful reload
}

var (
	_ cachable.Cacheable[any] = (*View[any])(nil)
	_ cachable.Mutable[any]   = (*View[any])(nil)
	_ cachable.Inspectable    = (*View[any])(nil)
	_ cachable.Tickable       = (*View[any])(nil)
)

// Current returns the current snapshot without blocking. It is nil before
// the Set is first loaded unless the view was registered via AddInitial.
func (v *View[T]) Current() *T {
	return v.ptr.Load()
}

// Due reports whether the owning set should be revalidated. It delegates to
// Set.Due, which honors RefreshInterval when set and otherwise treats the set
// as always due (upstreams own their own dedup windows).
func (v *View[T]) Due(ctx context.Context) (bool, error) {
	return v.set.Due(ctx)
}

// Revalidate asks the owning set to check its upstreams and returns whether
// this caller started the refresh.
func (v *View[T]) Revalidate(ctx context.Context) (bool, error) {
	return v.set.Revalidate(ctx)
}

// Load revalidates the owning set and returns this view's newest snapshot.
// On refresh failure, the last good snapshot is returned with the error.
func (v *View[T]) Load(ctx context.Context, wait bool) (*T, error) {
	if err := v.set.Load(ctx, wait); err != nil {
		return v.Current(), err
	}
	return v.Current(), nil
}

func (v *View[T]) Set(value *T) error {
	v.set.publishMu.Lock()
	defer v.set.publishMu.Unlock()
	v.set.generation.Add(1)
	previous := v.ptr.Swap(value)
	if previous != nil {
		if closer, ok := any(previous).(io.Closer); ok {
			_ = closer.Close()
		}
	}
	if value != nil {
		now := time.Now()
		v.loadedAt.Store(&now)
		v.set.loadedAt.Store(&now)
	}
	return nil
}

func (v *View[T]) Clear() error {
	return v.Set(nil)
}

// Status reports the view's published snapshot. StaleAt is populated from the
// set's RefreshInterval (when set); with a zero interval StaleAt stays zero
// because freshness is delegated to the upstreams.
func (v *View[T]) Status() cachable.Status {
	status := cachable.Status{HasValue: v.Current() != nil, Refreshing: v.set.refresh.Running()}
	if loadedAt := v.loadedAt.Load(); loadedAt != nil {
		status.LoadedAt = *loadedAt
		if v.set.RefreshInterval > 0 {
			status.StaleAt = status.LoadedAt.Add(v.set.RefreshInterval)
		}
	}
	return status
}

// Start starts the owning set's optional background ticker.
func (v *View[T]) Start(ctx context.Context, interval time.Duration) {
	v.set.Start(ctx, interval)
}

// Stop stops the owning set's optional background ticker and waits for any
// in-flight refresh to finish or reach RefreshTimeout.
func (v *View[T]) Stop() error {
	return v.set.Stop()
}

func (v *View[T]) prepare(ctx context.Context) (any, error) {
	return v.loader(ctx)
}

func (v *View[T]) publish(value any) {
	t := value.(*T)
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
}

func (v *View[T]) clear() {
	prev := v.ptr.Swap(nil)
	if prev != nil {
		if closer, ok := any(prev).(io.Closer); ok {
			_ = closer.Close()
		}
	}
}

// Add registers a new view in s and returns it. Call after NewSet and before
// the first Load. View.Current() returns nil until Set.Load succeeds.
// The loader receives the ctx passed to Set.Load, so long-running parses
// should honor ctx.Err() to support graceful shutdown.
//
// Panics if called after the first Load.
func Add[T any](s *Set, loader func(ctx context.Context) (*T, error)) *View[T] {
	if s.loaded.Load() {
		panic("dataset: Add called after Load")
	}
	v := &View[T]{set: s, loader: loader}
	s.views = append(s.views, v)
	return v
}

// AddInitial is like Add but pre-populates the view with initial, so
// View.Current() returns a usable (possibly empty) value before the first
// Load completes. Use when the initial state is benign (e.g. an empty
// cohort matches nothing) and you want to start serving before the
// first load finishes.
//
// Panics if called after the first Load.
func AddInitial[T any](s *Set, initial *T, loader func(ctx context.Context) (*T, error)) *View[T] {
	if s.loaded.Load() {
		panic("dataset: AddInitial called after Load")
	}
	v := &View[T]{set: s, loader: loader}
	v.ptr.Store(initial)
	s.views = append(s.views, v)
	return v
}
