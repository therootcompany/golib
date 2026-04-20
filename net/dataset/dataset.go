// Package dataset couples a Syncer (fetch) with a Loader (parse) and an
// atomic.Pointer (hot-swap), providing a generic periodically-updated
// in-memory dataset with lock-free reads.
//
// Standalone dataset (one syncer, one value):
//
//	ds := dataset.New(cacher, func() (*MyType, error) {
//	    return mytype.LoadFile(path)
//	})
//	if err := ds.Init(); err != nil { ... }
//	go ds.Run(ctx, 47*time.Minute)
//	val := ds.Load() // *MyType, lock-free
//
// Group (one syncer, multiple values — e.g. inbound+outbound from one git repo):
//
//	g := dataset.NewGroup(repo)
//	inbound  := dataset.Add(g, func() (*ipcohort.Cohort, error) { return ipcohort.LoadFiles(inboundPaths...) })
//	outbound := dataset.Add(g, func() (*ipcohort.Cohort, error) { return ipcohort.LoadFiles(outboundPaths...) })
//	if err := g.Init(); err != nil { ... }
//	go g.Run(ctx, 47*time.Minute)
package dataset

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/httpcache"
)

// Dataset couples a Syncer, a load function, and an atomic.Pointer[T].
// Load is safe for concurrent use without locks.
type Dataset[T any] struct {
	// Name is used in error messages. Optional.
	Name string
	// Close is called with the previous value after each successful swap.
	// Use this for values that hold resources, e.g. func(r *geoip2.Reader) { r.Close() }.
	Close func(*T)

	syncer httpcache.Syncer
	load   func() (*T, error)
	ptr    atomic.Pointer[T]
}

// New creates a Dataset. The syncer fetches updates; load produces the value.
// load is a closure — it captures whatever paths or config it needs.
func New[T any](syncer httpcache.Syncer, load func() (*T, error)) *Dataset[T] {
	return &Dataset[T]{syncer: syncer, load: load}
}

// Load returns the current value. Returns nil before Init is called.
func (d *Dataset[T]) Load() *T {
	return d.ptr.Load()
}

// Init fetches (if needed) then always loads, ensuring the dataset is
// populated on startup from an existing local file even if nothing changed.
func (d *Dataset[T]) Init() error {
	if _, err := d.syncer.Fetch(); err != nil {
		return err
	}
	return d.reload()
}

// Sync fetches and reloads if the content changed. Returns whether updated.
func (d *Dataset[T]) Sync() (bool, error) {
	updated, err := d.syncer.Fetch()
	if err != nil || !updated {
		return updated, err
	}
	return true, d.reload()
}

// Run calls Sync on every interval until ctx is done.
// Errors are written to stderr and do not stop the loop.
func (d *Dataset[T]) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if _, err := d.Sync(); err != nil {
				name := d.Name
				if name == "" {
					name = "dataset"
				}
				fmt.Fprintf(os.Stderr, "%s: sync error: %v\n", name, err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (d *Dataset[T]) reload() error {
	val, err := d.load()
	if err != nil {
		return err
	}
	if old := d.ptr.Swap(val); old != nil && d.Close != nil {
		d.Close(old)
	}
	return nil
}

// -- Group: one Syncer driving multiple datasets ---------------------------

// member is the type-erased reload handle stored in a Group.
type member interface {
	reload() error
}

// Group ties one Syncer to multiple datasets so a single Fetch drives all
// reloads — no redundant network calls when datasets share a source.
type Group struct {
	syncer  httpcache.Syncer
	members []member
}

// NewGroup creates a Group backed by syncer.
func NewGroup(syncer httpcache.Syncer) *Group {
	return &Group{syncer: syncer}
}

// View is the read-only handle returned by Add. It exposes only Load —
// fetch and reload are driven by the owning Group.
type View[T any] struct {
	d *Dataset[T]
}

// Load returns the current value. Returns nil before the Group is initialised.
func (v *View[T]) Load() *T { return v.d.ptr.Load() }

func (v *View[T]) reload() error { return v.d.reload() }

// Add registers a new dataset in g and returns a View. Call Load to read the
// current value. Drive updates by calling Init/Sync/Run on the Group.
// load is a closure capturing whatever paths or config it needs.
func Add[T any](g *Group, load func() (*T, error)) *View[T] {
	v := &View[T]{d: &Dataset[T]{load: load}}
	g.members = append(g.members, v)
	return v
}

// Init fetches once then reloads all registered datasets.
func (g *Group) Init() error {
	if _, err := g.syncer.Fetch(); err != nil {
		return err
	}
	return g.reloadAll()
}

// Sync fetches and reloads all datasets if the syncer reports an update.
func (g *Group) Sync() (bool, error) {
	updated, err := g.syncer.Fetch()
	if err != nil || !updated {
		return updated, err
	}
	return true, g.reloadAll()
}

// Run calls Sync on every interval until ctx is done.
func (g *Group) Run(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			if _, err := g.Sync(); err != nil {
				fmt.Fprintf(os.Stderr, "dataset group: sync error: %v\n", err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (g *Group) reloadAll() error {
	for _, m := range g.members {
		if err := m.reload(); err != nil {
			return err
		}
	}
	return nil
}
