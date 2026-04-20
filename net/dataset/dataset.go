// Package dataset couples a Syncer (fetch) with a Loader (parse) and an
// atomic.Pointer (hot-swap), providing a generic periodically-updated
// in-memory dataset with lock-free reads.
//
// Single dataset:
//
//	ds := dataset.New(cacher, ipcohort.LoadFile, path)
//	if err := ds.Init(); err != nil { ... }
//	go ds.Run(ctx, 47*time.Minute)
//	cohort := ds.Load()
//
// Multiple datasets sharing one syncer (e.g. inbound + outbound from one git repo):
//
//	g := dataset.NewGroup(repo)
//	inbound  := dataset.Add(g, ipcohort.LoadFile, inboundPath)
//	outbound := dataset.Add(g, ipcohort.LoadFile, outboundPath)
//	if err := g.Init(); err != nil { ... }
//	go g.Run(ctx, 47*time.Minute)
//	in  := inbound.Load()
//	out := outbound.Load()
package dataset

import (
	"context"
	"fmt"
	"os"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/httpcache"
)

// Loader reads path and returns the parsed value, or an error.
type Loader[T any] func(path string) (*T, error)

// Dataset couples a Syncer, a Loader, and an atomic.Pointer.
// Load is safe for concurrent use without locks.
type Dataset[T any] struct {
	syncer httpcache.Syncer
	load   Loader[T]
	path   string
	ptr    atomic.Pointer[T]
}

// New creates a Dataset. The syncer fetches updates to path; load parses it.
func New[T any](syncer httpcache.Syncer, load Loader[T], path string) *Dataset[T] {
	return &Dataset[T]{syncer: syncer, load: load, path: path}
}

// Load returns the current value. Returns nil before Init is called.
func (d *Dataset[T]) Load() *T {
	return d.ptr.Load()
}

// Init fetches (if the syncer needs it) then loads, ensuring the dataset is
// populated on startup from an existing local file even if nothing changed.
func (d *Dataset[T]) Init() error {
	if _, err := d.syncer.Fetch(); err != nil {
		return err
	}
	return d.reload()
}

// Sync fetches from the remote and reloads if the content changed.
// Returns whether the value was updated.
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
				fmt.Fprintf(os.Stderr, "dataset %s: sync error: %v\n", d.path, err)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (d *Dataset[T]) reload() error {
	val, err := d.load(d.path)
	if err != nil {
		return err
	}
	d.ptr.Store(val)
	return nil
}

// -- Group: one Syncer driving multiple datasets ---------------------------

// entry is the type-erased reload handle stored in a Group.
type entry interface {
	reload() error
}

// Group ties one Syncer to multiple datasets so a single Fetch drives all
// reloads — avoiding redundant network calls when datasets share a source
// (e.g. multiple files from the same git repo or HTTP directory).
type Group struct {
	syncer  httpcache.Syncer
	entries []entry
}

// NewGroup creates a Group backed by syncer.
func NewGroup(syncer httpcache.Syncer) *Group {
	return &Group{syncer: syncer}
}

// Add registers a new dataset in g and returns it. Subsequent Init/Sync/Run
// calls on g will reload this dataset whenever the syncer reports an update.
func Add[T any](g *Group, load Loader[T], path string) *Dataset[T] {
	d := &Dataset[T]{load: load, path: path}
	g.entries = append(g.entries, d)
	return d
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
	for _, e := range g.entries {
		if err := e.reload(); err != nil {
			return err
		}
	}
	return nil
}
