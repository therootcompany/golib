package iplist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// clearIPCache removes the on-disk httpcache entries so the next Load
// re-fetches from the source instead of serving the cached body.
func clearIPCache(t *testing.T, cacheDir string) {
	t.Helper()
	if err := os.RemoveAll(filepath.Join(cacheDir, "ip-sources")); err != nil {
		t.Fatalf("clear cache: %v", err)
	}
}

// newBlockingServer returns an httptest server whose first response serves
// the given body immediately (for the initial Load), and whose second
// response blocks until release is closed. The request count is recorded.
func newBlockingServer(body string) (srv *httptest.Server, release chan struct{}, hits *atomic.Int32) {
	release = make(chan struct{})
	hits = new(atomic.Int32)
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		// Block only on the second and later requests.
		if hits.Load() > 1 {
			select {
			case <-release:
			case <-r.Context().Done():
				return
			}
		}
		_, _ = w.Write([]byte(body))
	}))
	return srv, release, hits
}

// TestIPList_RevalidateCoalesces confirms concurrent Revalidate calls run the
// underlying fetch at most once while one is in flight.
func TestIPList_RevalidateCoalesces(t *testing.T) {
	srv, release, hits := newBlockingServer("192.0.2.1\n")
	defer srv.Close()

	// Initial load: configure a short interval so the first Load proceeds.
	src, err := NewIPList(t.Context(), IPListConfig{
		Source:          srv.URL,
		CacheDir:        t.TempDir(),
		RefreshInterval: time.Hour, // avoid re-due during the test
	})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Stop()

	// Stale the source so Revalidate is due, then make the next fetch block.
	clearIPCache(t, src.config.CacheDir)
	src.config.RefreshInterval = 0 // always due

	const n = 12
	var startedCount atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	wg.Add(n)
	for range n {
		go func() {
			defer wg.Done()
			<-start
			started, err := src.Revalidate(t.Context())
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
	// Allow the coalesced refresh to enter the blocking server exactly once.
	time.Sleep(30 * time.Millisecond)
	if got := hits.Load(); got != 2 {
		t.Fatalf("server hit %d times during in-flight refresh, want 2 (1 initial + 1 coalesced)", got)
	}
	close(release) // unblock the in-flight fetch
	wg.Wait()

	// Subsequent requests after release serve immediately; drain.
	if _, err := src.Load(t.Context(), true); err != nil {
		t.Logf("drain: %v", err)
	}
	if startedCount.Load() != 1 {
		t.Errorf("exactly one caller should have started, got %d", startedCount.Load())
	}
}

// TestIPList_SetDuringRefreshNotClobbered confirms the generation guard: a
// manual Set while a refresh is in flight is not overwritten by the stale
// refresh result.
func TestIPList_SetDuringRefreshNotClobbered(t *testing.T) {
	srv, release, hits := newBlockingServer("192.0.2.1\n")
	defer srv.Close()

	src, err := NewIPList(t.Context(), IPListConfig{
		Source:          srv.URL,
		CacheDir:        t.TempDir(),
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Stop()

	// Force due and start a blocking refresh.
	clearIPCache(t, src.config.CacheDir)
	src.config.RefreshInterval = 0
	if started, _ := src.Revalidate(t.Context()); !started {
		t.Fatal("Revalidate should start")
	}
	time.Sleep(20 * time.Millisecond)
	if hits.Load() != 2 {
		t.Fatalf("expected 1 in-flight fetch (2 total), got %d", hits.Load())
	}

	// Manually set entries while the refresh is blocked.
	manual := []string{"10.0.0.1"}
	if err := src.Set(&manual); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := src.Current(); got == nil || len(*got) != 1 || (*got)[0] != "10.0.0.1" {
		t.Fatalf("after Set Current = %v, want 10.0.0.1", got)
	}

	// Release the stale refresh; it must not overwrite the manual value.
	close(release)
	_, _ = src.Load(t.Context(), true)
	if got := src.Current(); got == nil || len(*got) != 1 || (*got)[0] != "10.0.0.1" {
		t.Errorf("after stale refresh Current = %v, want 10.0.0.1 (generation guard)", got)
	}
}

// TestIPList_ClearDuringRefreshPreventsPublication confirms Clear bumps the
// generation so an in-flight refresh does not republish.
func TestIPList_ClearDuringRefreshPreventsPublication(t *testing.T) {
	srv, release, hits := newBlockingServer("192.0.2.1\n")
	defer srv.Close()

	src, err := NewIPList(t.Context(), IPListConfig{
		Source:          srv.URL,
		CacheDir:        t.TempDir(),
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Stop()

	clearIPCache(t, src.config.CacheDir)
	src.config.RefreshInterval = 0
	if started, _ := src.Revalidate(t.Context()); !started {
		t.Fatal("Revalidate should start")
	}
	time.Sleep(20 * time.Millisecond)
	if hits.Load() != 2 {
		t.Fatalf("expected 1 in-flight fetch (2 total), got %d", hits.Load())
	}

	if err := src.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if src.Current() != nil {
		t.Fatal("Current should be nil after Clear")
	}

	close(release)
	_, _ = src.Load(t.Context(), true)
	if src.Current() != nil {
		t.Errorf("Current = %v after Clear+stale refresh, want nil (generation guard)", src.Current())
	}
}

// TestIPList_DetachedContextSurvivesCallerCancel confirms cancelling the
// caller context after Revalidate returns does not kill the background fetch.
func TestIPList_DetachedContextSurvivesCallerCancel(t *testing.T) {
	srv, release, hits := newBlockingServer("192.0.2.1\n")
	defer srv.Close()

	src, err := NewIPList(t.Context(), IPListConfig{
		Source:          srv.URL,
		CacheDir:        t.TempDir(),
		RefreshInterval: time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Stop()

	clearIPCache(t, src.config.CacheDir)
	src.config.RefreshInterval = 0
	ctx, cancel := context.WithCancel(t.Context())
	if started, err := src.Revalidate(ctx); err != nil || !started {
		t.Fatalf("Revalidate started=%v err=%v", started, err)
	}
	cancel()
	time.Sleep(30 * time.Millisecond)
	if got := hits.Load(); got != 2 {
		t.Fatalf("server hit %d times after caller cancel, want 2 (detached)", got)
	}
	close(release)
	if _, err := src.Load(t.Context(), true); err != nil {
		t.Fatalf("Load after cancel: %v", err)
	}
}

// TestIPList_KeepsLastGoodOnRefreshFailure is the file-source version of the
// existing http failure test, confirming last-good retention for a local
// source that disappears mid-run.
func TestIPList_KeepsLastGoodOnRefreshFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	src, err := NewIPList(t.Context(), IPListConfig{Source: path, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer src.Stop()

	if got := src.Current(); got == nil || len(*got) != 1 {
		t.Fatalf("initial = %#v", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	src.config.RefreshInterval = 0
	if _, err := src.Load(t.Context(), true); err == nil {
		t.Fatal("expected refresh error")
	}
	if got := src.Current(); got == nil || len(*got) != 1 || (*got)[0] != "192.0.2.1" {
		t.Errorf("last-good lost after failure: %#v", got)
	}
}
