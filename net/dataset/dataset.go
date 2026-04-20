// Package dataset couples a Syncer (fetch) with a Loader (parse) and an
// atomic.Pointer (hot-swap), providing a generic periodically-updated
// in-memory dataset with lock-free reads.
//
// Standalone dataset:
//
//	ds := dataset.New(cacher, func() (*MyType, error) {
//	    return mytype.LoadFile(path)
//	})
//	if err := ds.Init(); err != nil { ... }
//	go ds.Run(ctx, 47*time.Minute)
//	val := ds.Load() // *MyType, lock-free
//
// Group (one syncer, multiple values):
//
//	g := dataset.NewGroup(repo)
//	inbound  := dataset.Add(g, func() (*ipcohort.Cohort, error) { ... })
//	outbound := dataset.Add(g, func() (*ipcohort.Cohort, error) { ... })
//	if err := g.Init(); err != nil { ... }
//	go g.Run(ctx, 47*time.Minute)
package dataset

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// Syncer reports whether a remote resource has changed.
type Syncer interface {
	Fetch() (updated bool, err error)
}

// MultiSyncer fans out Fetch to multiple Syncers, returning updated=true if
// any reports a change. Stops and returns the first error.
type MultiSyncer []Syncer

func (ms MultiSyncer) Fetch() (bool, error) {
	var anyUpdated bool
	for _, s := range ms {
		updated, err := s.Fetch()
		if err != nil {
			return anyUpdated, err
		}
		anyUpdated = anyUpdated || updated
	}
	return anyUpdated, nil
}

// NopSyncer always reports no update. Use for local-file datasets.
type NopSyncer struct{}

func (NopSyncer) Fetch() (bool, error) { return false, nil }

// Dataset couples a Syncer, a load function, and an atomic.Pointer[T].
// Load is safe for concurrent use without locks.
type Dataset[T any] struct {
	// Name is used in error messages.
	Name string
	// Close is called with the old value after each successful swap.
	Close func(*T)

	syncer Syncer
	load   func() (*T, error)
	ptr    atomic.Pointer[T]
}

// New creates a Dataset. The syncer reports changes; load produces the value.
func New[T any](syncer Syncer, load func() (*T, error)) *Dataset[T] {
	return &Dataset[T]{syncer: syncer, load: load}
}

// Load returns the current value. Returns nil before Init is called.
func (d *Dataset[T]) Load() *T {
	return d.ptr.Load()
}

func (d *Dataset[T]) swap() error {
	val, err := d.load()
	if err != nil {
		return err
	}
	if old := d.ptr.Swap(val); old != nil && d.Close != nil {
		d.Close(old)
	}
	return nil
}

// Sync calls the syncer and, if updated, reloads and atomically installs the
// new value. Returns whether the source changed.
func (d *Dataset[T]) Sync() (bool, error) {
	updated, err := d.syncer.Fetch()
	if err != nil {
		return false, err
	}
	if !updated {
		return false, nil
	}
	return true, d.swap()
}

// Init syncs and always loads, ensuring the dataset is populated from an
// existing local file even if nothing changed upstream.
func (d *Dataset[T]) Init() error {
	if _, err := d.syncer.Fetch(); err != nil {
		return err
	}
	return d.swap()
}

// Run calls Sync on every interval. Errors are written to stderr and do not
// stop the loop.
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

// -- Group: one Syncer driving multiple datasets ---------------------------

// member is the type-erased swap handle stored in a Group.
type member interface {
	swap() error
}

// Group ties one Syncer to multiple datasets so a single Fetch drives all
// swaps — no redundant network calls when datasets share a source.
type Group struct {
	syncer  Syncer
	members []member
}

// NewGroup creates a Group backed by syncer.
func NewGroup(syncer Syncer) *Group {
	return &Group{syncer: syncer}
}

func (g *Group) swapAll() error {
	for _, m := range g.members {
		if err := m.swap(); err != nil {
			return err
		}
	}
	return nil
}

// Sync calls the syncer and, if updated, reloads all member datasets.
// Returns whether the source changed.
func (g *Group) Sync() (bool, error) {
	updated, err := g.syncer.Fetch()
	if err != nil {
		return false, err
	}
	if !updated {
		return false, nil
	}
	return true, g.swapAll()
}

// Init syncs and always loads all datasets.
func (g *Group) Init() error {
	if _, err := g.syncer.Fetch(); err != nil {
		return err
	}
	return g.swapAll()
}

// Run calls Sync on every interval; reloads all datasets only when the source
// reports a change.
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

// View is the read-only handle returned by Add. Sync is driven by the owning
// Group.
type View[T any] struct {
	d *Dataset[T]
}

// Load returns the current value. Returns nil before the Group is initialised.
func (v *View[T]) Load() *T { return v.d.ptr.Load() }

func (v *View[T]) swap() error { return v.d.swap() }

// Add registers a new dataset in g and returns a View for reading.
func Add[T any](g *Group, load func() (*T, error)) *View[T] {
	v := &View[T]{d: &Dataset[T]{load: load}}
	g.members = append(g.members, v)
	return v
}
