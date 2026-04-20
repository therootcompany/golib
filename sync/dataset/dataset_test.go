package dataset_test

import (
	"errors"
	"sync/atomic"
	"testing"

	"github.com/therootcompany/golib/sync/dataset"
)

type countFetcher struct {
	calls   atomic.Int32
	updated bool
	err     error
}

func (f *countFetcher) Fetch() (bool, error) {
	f.calls.Add(1)
	return f.updated, f.err
}

func TestGroup_LoadPopulatesAllViews(t *testing.T) {
	f := &countFetcher{}
	g := dataset.NewGroup(f)

	var aCalls, bCalls int
	a := dataset.Add(g, func() (*string, error) {
		aCalls++
		v := "a"
		return &v, nil
	})
	b := dataset.Add(g, func() (*int, error) {
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

func TestGroup_SecondLoadSkipsUnchanged(t *testing.T) {
	f := &countFetcher{updated: false}
	g := dataset.NewGroup(f)
	calls := 0
	dataset.Add(g, func() (*string, error) {
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

func TestGroup_LoadOnUpdateSwaps(t *testing.T) {
	f := &countFetcher{updated: true}
	g := dataset.NewGroup(f)
	n := 0
	v := dataset.Add(g, func() (*int, error) {
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

func TestGroup_ValueBeforeLoad(t *testing.T) {
	g := dataset.NewGroup(dataset.NopFetcher{})
	v := dataset.Add(g, func() (*string, error) {
		s := "x"
		return &s, nil
	})
	if v.Value() != nil {
		t.Error("Value() before Load should be nil")
	}
}

func TestGroup_FetchError(t *testing.T) {
	f := &countFetcher{err: errors.New("offline")}
	g := dataset.NewGroup(f)
	dataset.Add(g, func() (*string, error) {
		s := "x"
		return &s, nil
	})
	if err := g.Load(t.Context()); err == nil {
		t.Error("expected fetch error")
	}
}

func TestGroup_LoaderError(t *testing.T) {
	g := dataset.NewGroup(dataset.NopFetcher{})
	dataset.Add(g, func() (*string, error) {
		return nil, errors.New("parse fail")
	})
	if err := g.Load(t.Context()); err == nil {
		t.Error("expected loader error")
	}
}

func TestFetcherFunc(t *testing.T) {
	var called bool
	f := dataset.FetcherFunc(func() (bool, error) {
		called = true
		return true, nil
	})
	updated, err := f.Fetch()
	if err != nil {
		t.Fatal(err)
	}
	if !called || !updated {
		t.Errorf("FetcherFunc: called=%v updated=%v", called, updated)
	}
}
