package dataset_test

import (
	"context"
	"errors"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/therootcompany/golib/sync/dataset"
)

type countFetcher struct {
	calls   atomic.Int32
	updated bool
	err     error
}

func (f *countFetcher) Fetch(_ context.Context) (bool, error) {
	f.calls.Add(1)
	return f.updated, f.err
}

func TestSet_LoadPopulatesAllViews(t *testing.T) {
	f := &countFetcher{}
	g := dataset.NewSet(f)

	var aCalls, bCalls int
	a := dataset.Add(g, func(_ context.Context) (*string, error) {
		aCalls++
		v := "a"
		return &v, nil
	})
	b := dataset.Add(g, func(_ context.Context) (*int, error) {
		bCalls++
		v := 42
		return &v, nil
	})

	if err := g.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 1 {
		t.Errorf("Fetch called %d times, want 1", f.calls.Load())
	}
	if aCalls != 1 || bCalls != 1 {
		t.Errorf("loaders called (%d,%d), want (1,1)", aCalls, bCalls)
	}
	if got := a.Value(); got == nil || *got != "a" {
		t.Errorf("a.Value() = %v", got)
	}
	if got := b.Value(); got == nil || *got != 42 {
		t.Errorf("b.Value() = %v", got)
	}
}

func TestSet_SecondLoadSkipsUnchanged(t *testing.T) {
	f := &countFetcher{updated: false}
	g := dataset.NewSet(f)
	calls := 0
	dataset.Add(g, func(_ context.Context) (*string, error) {
		calls++
		v := "x"
		return &v, nil
	})
	if err := g.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("initial load ran loader %d times, want 1", calls)
	}
	if err := g.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("second load ran loader %d times, want 1 (no upstream change)", calls)
	}
}

func TestSet_LoadOnUpdateSwaps(t *testing.T) {
	f := &countFetcher{updated: true}
	g := dataset.NewSet(f)
	n := 0
	v := dataset.Add(g, func(_ context.Context) (*int, error) {
		n++
		return &n, nil
	})
	if err := g.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := g.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if got := v.Value(); got == nil || *got != 2 {
		t.Errorf("v.Value() = %v, want 2", got)
	}
}

func TestSet_FetchError(t *testing.T) {
	f := &countFetcher{err: errors.New("offline")}
	g := dataset.NewSet(f)
	dataset.Add(g, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := g.Load(t.Context()); err == nil {
		t.Error("expected fetch error")
	}
}

func TestSet_LoaderError(t *testing.T) {
	g := dataset.NewSet(dataset.NopFetcher{})
	dataset.Add(g, func(_ context.Context) (*string, error) {
		return nil, errors.New("parse fail")
	})
	if err := g.Load(t.Context()); err == nil {
		t.Error("expected loader error")
	}
}

func TestPollFiles(t *testing.T) {
	dir := t.TempDir()
	a := dir + "/a.txt"
	b := dir + "/b.txt"
	if err := os.WriteFile(a, []byte("1"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(b, []byte("2"), 0o644); err != nil {
		t.Fatal(err)
	}

	p := dataset.PollFiles(a, b)

	if u, err := p.Fetch(t.Context()); err != nil || !u {
		t.Fatalf("first Fetch: updated=%v err=%v, want true/nil", u, err)
	}
	if u, err := p.Fetch(t.Context()); err != nil || u {
		t.Fatalf("unchanged Fetch: updated=%v err=%v, want false/nil", u, err)
	}

	// Bump mtime + change contents on b.
	future := time.Now().Add(2 * time.Second)
	if err := os.WriteFile(b, []byte("22"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(b, future, future); err != nil {
		t.Fatal(err)
	}
	if u, err := p.Fetch(t.Context()); err != nil || !u {
		t.Errorf("after change: updated=%v err=%v, want true/nil", u, err)
	}
	if u, err := p.Fetch(t.Context()); err != nil || u {
		t.Errorf("steady Fetch: updated=%v err=%v, want false/nil", u, err)
	}
}

func TestSet_ClosePreventsTick(t *testing.T) {
	f := &countFetcher{updated: true}
	s := dataset.NewSet(f)
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 1
		return &n, nil
	})
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	go s.Tick(ctx, 10*time.Millisecond, nil)
	time.Sleep(30 * time.Millisecond) // let a few ticks fire

	// Close while Tick is still running.
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	cancel()
	time.Sleep(30 * time.Millisecond) // let more ticks fire

	// Value should be nil after Close.
	if v.Value() != nil {
		t.Error("Value() should be nil after Close")
	}
	// After Close, no further fetches should occur. The count should not
	// have increased between the Close and the final sleep.
	finalCalls := f.calls.Load()
	// Give the scheduler a moment to drain any in-flight Load calls.
	time.Sleep(10 * time.Millisecond)
	if f.calls.Load() != finalCalls {
		t.Errorf("fetch count increased after Close (%d → %d)", finalCalls, f.calls.Load())
	}
}

func TestSet_CloseIsIdempotent(t *testing.T) {
	s := dataset.NewSet(dataset.NopFetcher{})
	dataset.Add(s, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Error("second Close should be a no-op")
	}
	if err := s.Load(t.Context()); err == nil {
		t.Error("Load after Close should error")
	}
}

func TestSet_CloseNilsViews(t *testing.T) {
	s := dataset.NewSet(dataset.NopFetcher{})
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 42
		return &n, nil
	})
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	if v.Value() == nil || *v.Value() != 42 {
		t.Fatal("Value() should be 42 after Load")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if v.Value() != nil {
		t.Error("Value() should be nil after Close")
	}
}

func TestSet_AddAfterLoadPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Add after Load should panic")
		}
	}()
	s := dataset.NewSet(dataset.NopFetcher{})
	dataset.Add(s, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	dataset.Add(s, func(_ context.Context) (*string, error) {
		s := "y"
		return &s, nil
	})
}

func TestSet_AddInitialAfterLoadPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("AddInitial after Load should panic")
		}
	}()
	s := dataset.NewSet(dataset.NopFetcher{})
	dataset.Add(s, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := s.Load(t.Context()); err != nil {
		t.Fatal(err)
	}
	var x string
	dataset.AddInitial(s, &x, func(_ context.Context) (*string, error) {
		s := "y"
		return &s, nil
	})
}
