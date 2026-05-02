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

func TestSet_ValueBeforeLoad(t *testing.T) {
	g := dataset.NewSet(dataset.NopFetcher{})
	v := dataset.Add(g, func(_ context.Context) (*string, error) {
		s := "x"
		return &s, nil
	})
	if v.Value() != nil {
		t.Error("Value() before Load should be nil")
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

func TestPollFiles_MissingFile(t *testing.T) {
	p := dataset.PollFiles(t.TempDir() + "/nope.txt")
	if _, err := p.Fetch(t.Context()); err == nil {
		t.Error("expected error for missing file")
	}
}

func TestFetcherFunc(t *testing.T) {
	var called bool
	f := dataset.FetcherFunc(func(_ context.Context) (bool, error) {
		called = true
		return true, nil
	})
	updated, err := f.Fetch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !called || !updated {
		t.Errorf("FetcherFunc: called=%v updated=%v", called, updated)
	}
}
