package dataset_test

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/therootcompany/golib/net/dataset"
	"github.com/therootcompany/golib/net/httpcache"
)

// countSyncer counts Fetch calls and optionally reports updated.
type countSyncer struct {
	calls   atomic.Int32
	updated bool
	err     error
}

func (s *countSyncer) Fetch() (bool, error) {
	s.calls.Add(1)
	return s.updated, s.err
}

func TestDataset_Init(t *testing.T) {
	syn := &countSyncer{updated: false}
	calls := 0
	ds := dataset.New(syn, func() (*string, error) {
		calls++
		v := "hello"
		return &v, nil
	})

	if err := ds.Init(); err != nil {
		t.Fatal(err)
	}
	if got := ds.Load(); got == nil || *got != "hello" {
		t.Fatalf("Load() = %v, want \"hello\"", got)
	}
	if calls != 1 {
		t.Errorf("loader called %d times, want 1", calls)
	}
	if syn.calls.Load() != 1 {
		t.Errorf("Fetch called %d times, want 1", syn.calls.Load())
	}
}

func TestDataset_LoadBeforeInit(t *testing.T) {
	syn := httpcache.NopSyncer{}
	ds := dataset.New(syn, func() (*string, error) {
		v := "x"
		return &v, nil
	})
	if ds.Load() != nil {
		t.Error("Load() before Init should return nil")
	}
}

func TestDataset_SyncNoUpdate(t *testing.T) {
	syn := &countSyncer{updated: false}
	calls := 0
	ds := dataset.New(syn, func() (*string, error) {
		calls++
		v := "hello"
		return &v, nil
	})
	if err := ds.Init(); err != nil {
		t.Fatal(err)
	}
	calls = 0

	updated, err := ds.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if updated {
		t.Error("Sync() reported updated=true but syncer returned false")
	}
	if calls != 0 {
		t.Errorf("loader called %d times on no-update Sync, want 0", calls)
	}
}

func TestDataset_SyncWithUpdate(t *testing.T) {
	syn := &countSyncer{updated: true}
	n := 0
	ds := dataset.New(syn, func() (*string, error) {
		n++
		v := "v" + string(rune('0'+n))
		return &v, nil
	})
	if err := ds.Init(); err != nil {
		t.Fatal(err)
	}
	updated, err := ds.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if !updated {
		t.Error("Sync() reported updated=false but syncer returned true")
	}
	if got := ds.Load(); got == nil || *got != "v2" {
		t.Errorf("Load() after Sync = %v, want \"v2\"", got)
	}
}

func TestDataset_InitError(t *testing.T) {
	syn := &countSyncer{err: errors.New("fetch failed")}
	ds := dataset.New(syn, func() (*string, error) {
		v := "x"
		return &v, nil
	})
	if err := ds.Init(); err == nil {
		t.Error("expected error from Init when syncer fails")
	}
	if ds.Load() != nil {
		t.Error("Load() should be nil after failed Init")
	}
}

func TestDataset_LoaderError(t *testing.T) {
	syn := httpcache.NopSyncer{}
	ds := dataset.New(syn, func() (*string, error) {
		return nil, errors.New("load failed")
	})
	if err := ds.Init(); err == nil {
		t.Error("expected error from Init when loader fails")
	}
}

func TestDataset_Close(t *testing.T) {
	syn := &countSyncer{updated: true}
	var closed []string
	n := 0
	ds := dataset.New(syn, func() (*string, error) {
		n++
		v := "v" + string(rune('0'+n))
		return &v, nil
	})
	ds.Close = func(s *string) { closed = append(closed, *s) }

	if err := ds.Init(); err != nil {
		t.Fatal(err)
	}
	// First swap: old is nil, Close should not be called.
	if len(closed) != 0 {
		t.Errorf("Close called %d times on Init, want 0", len(closed))
	}

	if _, err := ds.Sync(); err != nil {
		t.Fatal(err)
	}
	if len(closed) != 1 || closed[0] != "v1" {
		t.Errorf("Close got %v, want [\"v1\"]", closed)
	}
}

func TestDataset_Run(t *testing.T) {
	syn := &countSyncer{updated: true}
	n := atomic.Int32{}
	ds := dataset.New(syn, func() (*int32, error) {
		v := n.Add(1)
		return &v, nil
	})
	if err := ds.Init(); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		ds.Run(ctx, 10*time.Millisecond)
		close(done)
	}()

	time.Sleep(60 * time.Millisecond)
	cancel()
	<-done

	if n.Load() < 2 {
		t.Errorf("Run did not tick: loader called %d times", n.Load())
	}
}

// --- Group tests ---

func TestGroup_Init(t *testing.T) {
	syn := &countSyncer{}
	g := dataset.NewGroup(syn)

	callsA, callsB := 0, 0
	dsA := dataset.Add(g, func() (*string, error) {
		callsA++
		v := "a"
		return &v, nil
	})
	dsB := dataset.Add(g, func() (*int, error) {
		callsB++
		v := 42
		return &v, nil
	})

	if err := g.Init(); err != nil {
		t.Fatal(err)
	}
	if syn.calls.Load() != 1 {
		t.Errorf("Fetch called %d times, want 1", syn.calls.Load())
	}
	if callsA != 1 || callsB != 1 {
		t.Errorf("loaders called (%d,%d), want (1,1)", callsA, callsB)
	}
	if got := dsA.Load(); got == nil || *got != "a" {
		t.Errorf("dsA.Load() = %v", got)
	}
	if got := dsB.Load(); got == nil || *got != 42 {
		t.Errorf("dsB.Load() = %v", got)
	}
}

func TestGroup_SyncNoUpdate(t *testing.T) {
	syn := &countSyncer{updated: false}
	g := dataset.NewGroup(syn)
	calls := 0
	dataset.Add(g, func() (*string, error) {
		calls++
		v := "x"
		return &v, nil
	})
	if err := g.Init(); err != nil {
		t.Fatal(err)
	}
	calls = 0

	updated, err := g.Sync()
	if err != nil {
		t.Fatal(err)
	}
	if updated || calls != 0 {
		t.Errorf("Sync() updated=%v calls=%d, want false/0", updated, calls)
	}
}

func TestGroup_SyncWithUpdate(t *testing.T) {
	syn := &countSyncer{updated: true}
	g := dataset.NewGroup(syn)
	n := 0
	ds := dataset.Add(g, func() (*int, error) {
		n++
		return &n, nil
	})
	if err := g.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := g.Sync(); err != nil {
		t.Fatal(err)
	}
	if got := ds.Load(); got == nil || *got != 2 {
		t.Errorf("ds.Load() = %v, want 2", got)
	}
}

func TestGroup_FetchError(t *testing.T) {
	syn := &countSyncer{err: errors.New("network down")}
	g := dataset.NewGroup(syn)
	dataset.Add(g, func() (*string, error) {
		v := "x"
		return &v, nil
	})
	if err := g.Init(); err == nil {
		t.Error("expected error from Group.Init when syncer fails")
	}
}

func TestGroup_LoaderError(t *testing.T) {
	syn := httpcache.NopSyncer{}
	g := dataset.NewGroup(syn)
	dataset.Add(g, func() (*string, error) {
		return nil, errors.New("parse error")
	})
	if err := g.Init(); err == nil {
		t.Error("expected error from Group.Init when loader fails")
	}
}
