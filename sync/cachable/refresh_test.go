package cachable

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestRefresh_BeginCoalesces confirms only one caller wins Begin while work is
// running; all others get false. This is the stampede-protection contract.
func TestRefresh_BeginCoalesces(t *testing.T) {
	var r Refresh
	if !r.Begin() {
		t.Fatal("first Begin must succeed")
	}
	for range 10 {
		if r.Begin() {
			t.Fatal("concurrent Begin must not succeed while running")
		}
	}
	if !r.Running() {
		t.Fatal("Running must be true after Begin")
	}
	r.Finish(nil)
	if r.Running() {
		t.Fatal("Running must be false after Finish")
	}
}

// TestRefresh_BeginAgainAfterFinish confirms the slot is reusable.
func TestRefresh_BeginAgainAfterFinish(t *testing.T) {
	var r Refresh
	r.Begin()
	r.Finish(nil)
	if !r.Begin() {
		t.Fatal("Begin must succeed after a finished refresh")
	}
	r.Finish(nil)
}

// TestRefresh_WaitBlocksUntilFinish confirms Wait blocks and then returns the
// refresh error.
func TestRefresh_WaitBlocksUntilFinish(t *testing.T) {
	var r Refresh
	r.Begin()

	want := errors.New("boom")
	go func() {
		time.Sleep(20 * time.Millisecond)
		r.Finish(want)
	}()

	if err := r.Wait(context.Background()); !errors.Is(err, want) {
		t.Errorf("Wait err = %v, want %v", err, want)
	}
}

// TestRefresh_WaitManyCallers confirms many concurrent waiters all observe the
// single Finish.
func TestRefresh_WaitManyCallers(t *testing.T) {
	var r Refresh
	r.Begin()

	const n = 20
	var wg sync.WaitGroup
	errs := make([]error, n)
	start := make(chan struct{})
	wg.Add(n)
	for i := range n {
		go func(i int) {
			defer wg.Done()
			<-start
			errs[i] = r.Wait(context.Background())
		}(i)
	}
	close(start)

	time.Sleep(20 * time.Millisecond)
	want := errors.New("fail")
	r.Finish(want)
	wg.Wait()

	for i, err := range errs {
		if !errors.Is(err, want) {
			t.Errorf("waiter %d err = %v, want %v", i, err, want)
		}
	}
}

// TestRefresh_WaitNoRunningReturnsStoredErr confirms that when no refresh is
// running, Wait returns the most recently completed refresh's error (the
// last-good/last-bad surface for callers that arrive after completion).
func TestRefresh_WaitNoRunningReturnsStoredErr(t *testing.T) {
	var r Refresh
	r.Begin()
	want := errors.New("persisted")
	r.Finish(want)

	if err := r.Wait(context.Background()); !errors.Is(err, want) {
		t.Errorf("Wait after finish err = %v, want %v", err, want)
	}
}

// TestRefresh_WaitKeepsItsRefreshResult confirms waiters retain the result
// belonging to the refresh they observed, even when the next refresh starts
// immediately after Finish.
func TestRefresh_WaitKeepsItsRefreshResult(t *testing.T) {
	var r Refresh
	if !r.Begin() {
		t.Fatal("initial Begin must succeed")
	}

	const n = 64
	results := make(chan error, n)
	for range n {
		go func() {
			results <- r.Wait(context.Background())
		}()
	}
	time.Sleep(10 * time.Millisecond)

	first := errors.New("first refresh failed")
	r.Finish(first)
	if !r.Begin() {
		t.Fatal("second Begin must succeed")
	}
	second := errors.New("second refresh failed")
	r.Finish(second)

	for range n {
		if err := <-results; !errors.Is(err, first) {
			t.Errorf("old waiter got %v, want %v", err, first)
		}
	}
}

// TestRefresh_BeginClearsErr confirms a new refresh clears the previous error
// so a stale failure is not surfaced to waiters of the new refresh.
func TestRefresh_BeginClearsErr(t *testing.T) {
	var r Refresh
	r.Begin()
	r.Finish(errors.New("old"))

	r.Begin()
	r.Finish(nil)

	if err := r.Wait(context.Background()); err != nil {
		t.Errorf("Wait after cleared refresh err = %v, want nil", err)
	}
}

// TestRefresh_WaitContextCancel confirms a caller can bail out of Wait.
func TestRefresh_WaitContextCancel(t *testing.T) {
	var r Refresh
	r.Begin()
	defer r.Finish(nil) // don't leak the goroutine slot

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := r.Wait(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Wait err = %v, want DeadlineExceeded", err)
	}
}

// TestRefresh_StopWaitsAndPreventsNewRuns confirms Stop is a lifecycle barrier.
func TestRefresh_StopWaitsAndPreventsNewRuns(t *testing.T) {
	var r Refresh
	if !r.Begin() {
		t.Fatal("Begin must succeed")
	}
	want := errors.New("persist failure")
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done <- r.Stop(ctx)
	}()
	time.Sleep(10 * time.Millisecond)
	if r.Begin() {
		t.Fatal("Begin must fail after Stop claims the coordinator")
	}
	select {
	case err := <-done:
		t.Fatalf("Stop returned before refresh finished: %v", err)
	default:
	}
	r.Finish(want)
	if err := <-done; !errors.Is(err, want) {
		t.Errorf("Stop err = %v, want %v", err, want)
	}
	if r.Begin() {
		t.Fatal("Begin must remain disabled after Stop")
	}
}

// TestRefresh_StopHonorsTimeout confirms Stop returns its timeout error when
// the in-flight refresh does not finish before the shutdown deadline.
func TestRefresh_StopHonorsTimeout(t *testing.T) {
	var r Refresh
	r.Begin()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := r.Stop(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Errorf("Stop err = %v, want DeadlineExceeded", err)
	}
	r.Finish(nil)
}

// TestRefresh_RunningIsLockFree is a smoke test that Running does not need the
// mutex (no deadlock under contention). It races Running against Begin/Finish.
func TestRefresh_RunningUnderContention(t *testing.T) {
	var r Refresh
	var stop atomic.Bool
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for !stop.Load() {
			if r.Begin() {
				time.Sleep(time.Microsecond)
				r.Finish(nil)
			}
		}
	}()
	go func() {
		defer wg.Done()
		for !stop.Load() {
			_ = r.Running()
		}
	}()
	time.Sleep(50 * time.Millisecond)
	stop.Store(true)
	wg.Wait()
}
