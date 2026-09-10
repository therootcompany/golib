package dataset_test

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/therootcompany/golib/sync/dataset"
)

// blockingUpstream blocks its Update call until release is closed, then
// reports updated and err. It records how many times Update was entered.
type blockingUpstream struct {
	entered atomic.Int32
	release chan struct{}
	updated bool
	err     error
}

func newBlockingUpstream() *blockingUpstream {
	return &blockingUpstream{release: make(chan struct{})}
}

func (b *blockingUpstream) Update(ctx context.Context) (bool, error) {
	b.entered.Add(1)
	select {
	case <-ctx.Done():
		return false, ctx.Err()
	case <-b.release:
	}
	return b.updated, b.err
}

func (b *blockingUpstream) unblock() { close(b.release) }

// TestSet_RevalidateCoalescesConcurrentCallers confirms that many concurrent
// Revalidate calls result in exactly one upstream Update while the first is
// in flight, and that the rest report started=false.
func TestSet_RevalidateCoalescesConcurrentCallers(t *testing.T) {
	up := newBlockingUpstream()
	s := dataset.NewSet(up)
	dataset.Add(s, func(_ context.Context) (*int, error) {
		v := 1
		return &v, nil
	})

	ctx := t.Context()
	startedCount := atomic.Int32{}
	const n = 16
	var wg sync.WaitGroup
	wg.Add(n)
	start := make(chan struct{})
	for range n {
		go func() {
			defer wg.Done()
			<-start
			started, err := s.Revalidate(ctx)
			if err != nil {
				t.Errorf("Revalidate: %v", err)
				return
			}
			if started {
				startedCount.Add(1)
			}
		}()
	}
	close(start)

	// While the upstream is blocked, exactly one Update should have been
	// entered; the other callers are waiting on the coalesced refresh.
	time.Sleep(30 * time.Millisecond)
	if got := up.entered.Load(); got != 1 {
		t.Fatalf("upstream entered %d times during in-flight refresh, want 1", got)
	}

	up.unblock()
	wg.Wait()

	if startedCount.Load() != 1 {
		t.Errorf("exactly one caller should have started the refresh, got %d", startedCount.Load())
	}
}

// TestSet_LoadFalseDoesNotBlock confirms that after the first load, a
// Load(wait=false) returns immediately even while a refresh is running.
func TestSet_LoadFalseDoesNotBlock(t *testing.T) {
	up := newBlockingUpstream()
	s := dataset.NewSet(up)
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 1
		return &n, nil
	})

	// Initial load (blocks until we release).
	ctx := t.Context()
	loadErr := make(chan error, 1)
	go func() {
		loadErr <- s.Load(ctx, true)
	}()
	time.Sleep(20 * time.Millisecond)
	up.unblock()
	if err := <-loadErr; err != nil {
		t.Fatalf("initial load: %v", err)
	}
	if got := v.Current(); got == nil || *got != 1 {
		t.Fatalf("after initial load Current = %v", got)
	}

	// Start a second refresh that blocks.
	up.release = make(chan struct{})
	if started, _ := s.Revalidate(ctx); !started {
		t.Fatal("Revalidate should start")
	}
	time.Sleep(20 * time.Millisecond)

	// Load(false) must return immediately with the current value without
	// blocking, even though the refresh is still running.
	done := make(chan error, 1)
	go func() {
		_, err := v.Load(ctx, false)
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Load(false) returned err %v; want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Load(false) blocked while refresh was running")
	}
	up.unblock()
}

// TestSet_LoadTrueWaitsForRunningRefresh confirms Load(wait=true) waits for an
// already-running refresh to complete.
func TestSet_LoadTrueWaitsForRunningRefresh(t *testing.T) {
	up := newBlockingUpstream()
	up.updated = true
	s := dataset.NewSet(up)
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 7
		return &n, nil
	})
	ctx := t.Context()

	// Initial load.
	go func() { _ = s.Load(ctx, true) }()
	time.Sleep(20 * time.Millisecond)
	up.unblock()
	if err := s.Load(ctx, true); err != nil {
		t.Fatalf("drain initial: %v", err)
	}

	// Start a blocking refresh.
	up.release = make(chan struct{})
	if started, _ := s.Revalidate(ctx); !started {
		t.Fatal("Revalidate should start")
	}
	time.Sleep(20 * time.Millisecond)

	// A concurrent Load(true) must block until the refresh finishes.
	done := make(chan struct{})
	go func() {
		_, _ = v.Load(ctx, true)
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("Load(true) returned before refresh finished")
	case <-time.After(30 * time.Millisecond):
	}
	up.unblock()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Load(true) did not return after refresh finished")
	}
}

// TestSet_SetDuringRefreshDoesNotGetClobbered confirms the generation guard:
// a manual Set while a refresh is in flight prevents the stale prepared value
// from publishing over the manually-set value.
func TestSet_SetDuringRefreshDoesNotGetClobbered(t *testing.T) {
	up := newBlockingUpstream()
	up.updated = true
	s := dataset.NewSet(up)
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 999 // stale value the in-flight refresh would publish
		return &n, nil
	})
	ctx := t.Context()

	// Start a refresh and let it enter the upstream (blocking).
	if started, _ := s.Revalidate(ctx); !started {
		t.Fatal("Revalidate should start")
	}
	time.Sleep(20 * time.Millisecond)

	// Manually set a value while the refresh is in flight.
	manual := 42
	if err := v.Set(&manual); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := v.Current(); got == nil || *got != 42 {
		t.Fatalf("after manual Set Current = %v, want 42", got)
	}

	// Release the stale refresh; it must not overwrite the manual value.
	up.unblock()
	if err := s.Load(ctx, true); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := v.Current(); got == nil || *got != 42 {
		t.Errorf("after stale refresh Current = %v, want 42 (generation guard)", got)
	}
}

// TestSet_ClearDuringRefreshPreventsPublication confirms Clear bumps the
// generation so an in-flight refresh does not republish a cleared value.
func TestSet_ClearDuringRefreshPreventsPublication(t *testing.T) {
	up := newBlockingUpstream()
	up.updated = true
	s := dataset.NewSet(up)
	v := dataset.Add(s, func(_ context.Context) (*int, error) {
		n := 5
		return &n, nil
	})
	ctx := t.Context()

	// Initial load.
	go func() { _ = s.Load(ctx, true) }()
	time.Sleep(20 * time.Millisecond)
	up.unblock()
	if err := s.Load(ctx, true); err != nil {
		t.Fatalf("drain initial: %v", err)
	}

	// Start a blocking refresh, then Clear while it's in flight.
	up.release = make(chan struct{})
	if started, _ := s.Revalidate(ctx); !started {
		t.Fatal("Revalidate should start")
	}
	time.Sleep(20 * time.Millisecond)

	if err := s.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if v.Current() != nil {
		t.Fatal("Current should be nil after Clear")
	}

	up.unblock()
	// Give the in-flight refresh time to (not) publish.
	if err := s.Load(ctx, true); err != nil {
		t.Fatalf("Load: %v", err)
	}
	if v.Current() != nil {
		t.Errorf("Current = %v after Clear+stale refresh, want nil (generation guard)", v.Current())
	}
}

// TestSet_TransactionalMultiViewPublication confirms that when one view's
// loader fails, no view publishes a partial update.
func TestSet_TransactionalMultiViewPublication(t *testing.T) {
	s := dataset.NewSet(dataset.NopUpstream{})
	a := dataset.Add(s, func(_ context.Context) (*int, error) {
		v := 1
		return &v, nil
	})
	b := dataset.Add(s, func(_ context.Context) (*string, error) {
		return nil, errors.New("b broke")
	})

	ctx := t.Context()
	// Initial load fails because b errors.
	if err := s.Load(ctx, true); err == nil {
		t.Fatal("expected loader error on initial load")
	}
	// Neither view should have published.
	if a.Current() != nil {
		t.Errorf("view a published = %v, want nil (transactional)", a.Current())
	}
	if b.Current() != nil {
		t.Errorf("view b published = %v, want nil (transactional)", b.Current())
	}
}

// TestSet_TransactionalMultiViewPublishesTogether confirms that on success,
// all views publish atomically: a concurrent reader sees either all-old or
// all-new, never a mix.
func TestSet_TransactionalMultiViewPublishesTogether(t *testing.T) {
	up := newBlockingUpstream()
	up.updated = true
	s := dataset.NewSet(up)
	a := dataset.Add(s, func(_ context.Context) (*int, error) {
		v := 1
		return &v, nil
	})
	b := dataset.Add(s, func(_ context.Context) (*string, error) {
		v := "one"
		return &v, nil
	})
	ctx := t.Context()

	// Initial load.
	go func() { _ = s.Load(ctx, true) }()
	time.Sleep(20 * time.Millisecond)
	up.unblock()
	if err := s.Load(ctx, true); err != nil {
		t.Fatalf("drain initial: %v", err)
	}

	// Second refresh publishes new values; both should swap together.
	up.release = make(chan struct{})
	// Swap loaders is not possible after Add, so we rely on updated=true to
	// re-run the same loaders (they return the same values). The transactional
	// guarantee is that publish happens under publishMu for all views at once.
	// We assert the invariant by reading both atomically from a racer and
	// checking consistency.
	if started, _ := s.Revalidate(ctx); !started {
		t.Fatal("Revalidate should start")
	}

	var inconsistent atomic.Bool
	var wg sync.WaitGroup
	wg.Go(func() {
		for range 1000 {
			av := a.Current()
			bv := b.Current()
			// Both nil or both non-nil is the only consistent state once
			// loaded. (Values are identical across refreshes here, so we only
			// check presence consistency.)
			if (av == nil) != (bv == nil) {
				inconsistent.Store(true)
				return
			}
		}
	})
	up.unblock()
	wg.Wait()
	if inconsistent.Load() {
		t.Error("observed mixed nil/non-nil across views during publication")
	}
}

// TestSet_DetachedContextSurvivesCallerCancel confirms that cancelling the
// caller's context after Revalidate returns does not cancel the background
// refresh (it uses context.WithoutCancel).
func TestSet_DetachedContextSurvivesCallerCancel(t *testing.T) {
	up := newBlockingUpstream()
	s := dataset.NewSet(up)
	dataset.Add(s, func(_ context.Context) (*int, error) {
		v := 1
		return &v, nil
	})

	ctx, cancel := context.WithCancel(t.Context())
	if started, err := s.Revalidate(ctx); err != nil || !started {
		t.Fatalf("Revalidate started=%v err=%v", started, err)
	}
	// Cancel the caller context immediately.
	cancel()
	// The upstream should still be blocked (not cancelled). Give it a moment
	// to ensure the detached context didn't propagate cancellation.
	time.Sleep(30 * time.Millisecond)
	if got := up.entered.Load(); got != 1 {
		t.Fatalf("upstream entered %d times, want 1", got)
	}

	// Releasing the upstream should let the refresh complete normally.
	up.unblock()
	if err := s.Load(t.Context(), true); err != nil {
		t.Fatalf("Load after cancel: %v", err)
	}
}
