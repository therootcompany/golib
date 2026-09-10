package cacheable

import (
	"context"
	"sync"
	"sync/atomic"
)

// Refresh coordinates one in-flight refresh. It is for cache implementations;
// callers normally use Cacheable rather than this type directly.
//
// Running is lock-free (atomic.Bool) so hot-path callers that only need to
// check whether a refresh is in flight never contend on the mutex. Begin,
// Finish, and Wait use a mutex to publish and coordinate each run's result.
type Refresh struct {
	mu      sync.Mutex
	run     atomic.Bool
	stopped bool
	state   *refreshState
}

type refreshState struct {
	done chan struct{}
	err  error
}

// Begin claims the refresh slot. It returns false when work is already running.
func (r *Refresh) Begin() bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.stopped || r.run.Load() {
		return false
	}
	r.state = &refreshState{done: make(chan struct{})}
	r.run.Store(true)
	return true
}

func (r *Refresh) Finish(err error) {
	r.mu.Lock()
	state := r.state
	state.err = err
	close(state.done)
	r.run.Store(false)
	r.mu.Unlock()
}

// Running reports whether a refresh is in flight. It is lock-free.
func (r *Refresh) Running() bool {
	return r.run.Load()
}

// Stop prevents future refreshes and waits for the current refresh, if any.
// The caller supplies the shutdown deadline. If the refresh finishes before
// that deadline, Stop returns its update/persistence error; otherwise it
// returns ctx.Err().
func (r *Refresh) Stop(ctx context.Context) error {
	r.mu.Lock()
	r.stopped = true
	state := r.state
	running := r.run.Load()
	r.mu.Unlock()
	if !running || state == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-state.done:
		return state.err
	}
}

// Wait blocks until the in-flight refresh completes and returns its error.
// If no refresh is running, it returns the error of the most recently completed
// refresh (nil if none has run). The stored error is cleared by the next
// Begin, so repeat callers see only the latest outcome. For first-load this
// always surfaces the refresh error: Load calls Revalidate (which Begins)
// before Wait, so the refresh this caller started is still running when Wait
// observes it via the done channel. Callers wanting the authoritative last
// error rather than a per-call wait result should read Status.LastError.
func (r *Refresh) Wait(ctx context.Context) error {
	r.mu.Lock()
	state := r.state
	if !r.run.Load() {
		if state == nil {
			r.mu.Unlock()
			return nil
		}
		err := state.err
		r.mu.Unlock()
		return err
	}
	r.mu.Unlock()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-state.done:
		return state.err
	}
}
