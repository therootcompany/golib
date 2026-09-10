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

type countUpdater struct {
	calls   atomic.Int32
	updated bool
	err     error
}

func (f *countUpdater) Update(_ context.Context) (bool, error) {
	f.calls.Add(1)
	return f.updated, f.err
}

func TestSet_LoadPopulatesAllViews(t *testing.T) {
	f := &countUpdater{}
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

	if err := g.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != 1 {
		t.Errorf("Fetch called %d times, want 1", f.calls.Load())
	}
	if aCalls != 1 || bCalls != 1 {
		t.Errorf("loaders called (%d,%d), want (1,1)", aCalls, bCalls)
	}
	if got := a.Current(); got == nil || *got != "a" {
		t.Errorf("a.Current() = %v", got)
	}
	if got := b.Current(); got == nil || *got != 42 {
		t.Errorf("b.Current() = %v", got)
	}
}

func TestSet_SecondLoadSkipsUnchanged(t *testing.T) {
	f := &countUpdater{updated: false}
	g := dataset.NewSet(f)
	calls := 0
	dataset.Add(g, func(_ context.Context) (*string, error) {
		calls++
		v := "x"
		return &v, nil
	})
	if err := g.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("initial load ran loader %d times, want 1", calls)
	}
	if err := g.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Errorf("second load ran loader %d times, want 1 (no upstream change)", calls)
	}
}

func TestSet_LoadOnUpdateSwaps(t *testing.T) {
	f := &countUpdater{updated: true}
	g := dataset.NewSet(f)
	n := 0
	v := dataset.Add(g, func(_ context.Context) (*int, error) {
		n++
		return &n, nil
	})
	if err := g.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := g.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if got := v.Current(); got == nil || *got != 2 {
		t.Errorf("v.Current() = %v, want 2", got)
	}
}

func TestSet_FetchError(t *testing.T) {
	f := &countUpdater{err: errors.New("offline")}
	g := dataset.NewSet(f)
	dataset.Add(g, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := g.Load(t.Context(), true); err == nil {
		t.Error("expected fetch error")
	}
}

func TestSet_LoaderError(t *testing.T) {
	g := dataset.NewSet(dataset.NopUpstream{})
	dataset.Add(g, func(_ context.Context) (*string, error) {
		return nil, errors.New("parse fail")
	})
	if err := g.Load(t.Context(), true); err == nil {
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

	if u, err := p.Update(t.Context()); err != nil || !u {
		t.Fatalf("first Fetch: updated=%v err=%v, want true/nil", u, err)
	}
	if u, err := p.Update(t.Context()); err != nil || u {
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
	if u, err := p.Update(t.Context()); err != nil || !u {
		t.Errorf("after change: updated=%v err=%v, want true/nil", u, err)
	}
	if u, err := p.Update(t.Context()); err != nil || u {
		t.Errorf("steady Fetch: updated=%v err=%v, want false/nil", u, err)
	}
}

func TestSet_DueGatesRevalidateByInterval(t *testing.T) {
	f := &countUpdater{updated: false}
	s := dataset.NewSet(f)
	s.RefreshInterval = 30 * time.Millisecond
	dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 1
		return &n, nil
	})

	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	first := f.calls.Load()
	if first != 1 {
		t.Fatalf("initial load calls = %d, want 1", first)
	}

	// Within the interval, Revalidate must not start a refresh.
	for range 3 {
		if started, err := s.Revalidate(t.Context()); err != nil {
			t.Fatalf("Revalidate: %v", err)
		} else if started {
			t.Error("Revalidate started work before StaleAt")
		}
	}
	if f.calls.Load() != first {
		t.Errorf("upstream checked %d times within interval, want %d", f.calls.Load(), first)
	}

	// After the interval elapses, Revalidate starts a refresh.
	time.Sleep(35 * time.Millisecond)
	if started, err := s.Revalidate(t.Context()); err != nil {
		t.Fatalf("Revalidate after stale: %v", err)
	} else if !started {
		t.Error("Revalidate should start work after StaleAt")
	}
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if f.calls.Load() != first+1 {
		t.Errorf("upstream checked %d times after stale, want %d", f.calls.Load(), first+1)
	}
}

func TestSet_DueAlwaysTrueWithoutInterval(t *testing.T) {
	f := &countUpdater{updated: false}
	s := dataset.NewSet(f) // RefreshInterval == 0
	dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 1
		return &n, nil
	})
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	// With no interval, every Revalidate is due and starts a refresh (coalesced
	// if one is already running). Upstreams own their own dedup.
	if started, err := s.Revalidate(t.Context()); err != nil {
		t.Fatalf("Revalidate: %v", err)
	} else if !started {
		t.Error("Revalidate should start with zero interval")
	}
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
}

func TestSet_ClearStopsTicker(t *testing.T) {
	f := &countUpdater{updated: true}
	s := dataset.NewSet(f)
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 1
		return &n, nil
	})
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	s.Start(ctx, 10*time.Millisecond)
	time.Sleep(30 * time.Millisecond) // let a few ticks fire

	// Cancel the ticker before clearing so no new refresh starts after Clear.
	cancel()
	time.Sleep(20 * time.Millisecond) // let in-flight refresh drain

	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	time.Sleep(30 * time.Millisecond) // no more ticks should fire

	// Current should be nil after Clear.
	if v.Current() != nil {
		t.Error("Current() should be nil after Clear")
	}
	// After cancellation, no further fetches should occur.
	finalCalls := f.calls.Load()
	time.Sleep(10 * time.Millisecond)
	if f.calls.Load() != finalCalls {
		t.Errorf("fetch count increased after cancel (%d → %d)", finalCalls, f.calls.Load())
	}
}

func TestSet_ClearIsIdempotent(t *testing.T) {
	s := dataset.NewSet(dataset.NopUpstream{})
	dataset.Add(s, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if err := s.Clear(); err != nil {
		t.Error("second Clear should be a no-op")
	}
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatalf("Load after Clear: %v", err)
	}
}

func TestSet_ClearThenLoadRepublishes(t *testing.T) {
	s := dataset.NewSet(dataset.NopUpstream{})
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 42
		return &n, nil
	})
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if v.Current() == nil || *v.Current() != 42 {
		t.Fatal("expected 42 after initial load")
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if v.Current() != nil {
		t.Fatal("expected nil after Clear")
	}
	// After Clear, Load must repopulate the view even when the upstream
	// reports no change (NopUpstream returns false). Previously, loaded
	// stayed true after Clear, so update skipped reloading.
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatalf("Load after Clear: %v", err)
	}
	if v.Current() == nil {
		t.Fatal("view is nil after Load following Clear")
	}
	if *v.Current() != 42 {
		t.Errorf("got %d, want 42", *v.Current())
	}
}

func TestSet_ClearNilsViews(t *testing.T) {
	s := dataset.NewSet(dataset.NopUpstream{})
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 42
		return &n, nil
	})
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	if v.Current() == nil || *v.Current() != 42 {
		t.Fatal("Current() should be 42 after Load")
	}
	if err := s.Clear(); err != nil {
		t.Fatal(err)
	}
	if v.Current() != nil {
		t.Error("Current() should be nil after Clear")
	}
}

func TestSet_AddAfterLoadPanic(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("Add after Load should panic")
		}
	}()
	s := dataset.NewSet(dataset.NopUpstream{})
	dataset.Add(s, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := s.Load(t.Context(), true); err != nil {
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
	s := dataset.NewSet(dataset.NopUpstream{})
	dataset.Add(s, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatal(err)
	}
	var x string
	dataset.AddInitial(s, &x, func(_ context.Context) (*string, error) {
		s := "y"
		return &s, nil
	})
}
