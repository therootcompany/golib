package httpcache_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/therootcompany/golib/net/httpcache"
)

// fakeServer serves body with a fixed ETag and honors If-None-Match.
// hits counts how many requests reached the handler, including 304s.
type fakeServer struct {
	body []byte
	etag string
	hits atomic.Int32
}

func (f *fakeServer) handler(w http.ResponseWriter, r *http.Request) {
	f.hits.Add(1)
	if r.Header.Get("If-None-Match") == f.etag {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	w.Header().Set("ETag", f.etag)
	w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
	_, _ = w.Write(f.body)
}

func TestCacher_Download(t *testing.T) {
	fs := &fakeServer{body: []byte("hello blocklist\n"), etag: `"abc123"`}
	srv := httptest.NewServer(http.HandlerFunc(fs.handler))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)

	updated, err := c.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if !updated {
		t.Error("first Fetch: expected updated=true")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	if string(got) != string(fs.body) {
		t.Errorf("body = %q, want %q", got, fs.body)
	}
}

func TestCacher_SidecarWritten(t *testing.T) {
	fs := &fakeServer{body: []byte("x"), etag: `"sidecar-etag"`}
	srv := httptest.NewServer(http.HandlerFunc(fs.handler))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	if _, err := c.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	data, err := os.ReadFile(path + ".meta")
	if err != nil {
		t.Fatalf("sidecar not written: %v", err)
	}
	var meta map[string]string
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("sidecar not valid JSON: %v", err)
	}
	if meta["etag"] != fs.etag {
		t.Errorf("sidecar etag = %q, want %q", meta["etag"], fs.etag)
	}
	if meta["last_modified"] == "" {
		t.Error("sidecar last_modified empty")
	}
}

func TestCacher_ConditionalGet_SameCacher(t *testing.T) {
	fs := &fakeServer{body: []byte("body"), etag: `"e1"`}
	srv := httptest.NewServer(http.HandlerFunc(fs.handler))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	if _, err := c.Fetch(t.Context()); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}

	updated, err := c.Fetch(t.Context())
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if updated {
		t.Error("second Fetch: expected updated=false (304 path)")
	}
	if got := fs.hits.Load(); got != 2 {
		t.Errorf("server hits = %d, want 2 (both Fetches must reach the wire)", got)
	}
}

func TestCacher_ConditionalGet_FreshCacher(t *testing.T) {
	// Fresh Cacher must read the sidecar and send If-None-Match — proves
	// ETag survives process restart.
	fs := &fakeServer{body: []byte("body"), etag: `"e2"`}
	srv := httptest.NewServer(http.HandlerFunc(fs.handler))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	if _, err := httpcache.New(srv.URL, path).Fetch(t.Context()); err != nil {
		t.Fatalf("seed Fetch: %v", err)
	}

	fresh := httpcache.New(srv.URL, path)
	updated, err := fresh.Fetch(t.Context())
	if err != nil {
		t.Fatalf("fresh Fetch: %v", err)
	}
	if updated {
		t.Error("fresh Fetch: expected updated=false (sidecar should have provided ETag)")
	}
}

func TestCacher_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := httpcache.New(srv.URL, filepath.Join(t.TempDir(), "data.txt"))
	_, err := c.Fetch(t.Context())
	if !errors.Is(err, httpcache.ErrUnexpectedStatus) {
		t.Errorf("err = %v, want ErrUnexpectedStatus", err)
	}
}

func TestCacher_EmptyResponse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	c := httpcache.New(srv.URL, filepath.Join(t.TempDir(), "data.txt"))
	_, err := c.Fetch(t.Context())
	if !errors.Is(err, httpcache.ErrEmptyResponse) {
		t.Errorf("err = %v, want ErrEmptyResponse", err)
	}
}

func TestCacher_MaxAgeBacksOffAfterFailure(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.MaxAge = time.Hour
	if _, err := c.Fetch(t.Context()); !errors.Is(err, httpcache.ErrUnexpectedStatus) {
		t.Fatalf("first Fetch: %v, want ErrUnexpectedStatus", err)
	}

	// The failed attempt is persisted, so a new process also waits instead
	// of retrying immediately against the rate-limited server.
	fresh := httpcache.New(srv.URL, path)
	fresh.MaxAge = time.Hour
	updated, err := fresh.Fetch(t.Context())
	if err != nil {
		t.Fatalf("backoff Fetch: %v", err)
	}
	if updated {
		t.Error("backoff Fetch: updated=true, want false")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1", got)
	}
}

func TestCacher_RetryAfterOverridesFailureBackoff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Header().Set("Retry-After", "3600")
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.FailureBackoff = time.Second
	if _, err := c.Fetch(t.Context()); !errors.Is(err, httpcache.ErrUnexpectedStatus) {
		t.Fatalf("first Fetch: %v, want ErrUnexpectedStatus", err)
	}

	fresh := httpcache.New(srv.URL, path)
	updated, err := fresh.Fetch(t.Context())
	if err != nil {
		t.Fatalf("Retry-After Fetch: %v", err)
	}
	if updated {
		t.Error("Retry-After Fetch: updated=true, want false")
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1", got)
	}
}

func TestCacher_MaxBytesExceeded(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("0123456789ABCDEF")) // 16 bytes
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.MaxBytes = 8
	_, err := c.Fetch(t.Context())
	if !errors.Is(err, httpcache.ErrBodyTooLarge) {
		t.Errorf("err = %v, want ErrBodyTooLarge", err)
	}
	if _, statErr := os.Stat(path); statErr == nil {
		t.Error("expected body file not to be present after MaxBytes failure")
	}
}

func TestCacher_PeerFetching(t *testing.T) {
	fs := &fakeServer{body: []byte("body"), etag: `"e1"`}
	srv := httptest.NewServer(http.HandlerFunc(fs.handler))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)

	// First Fetch establishes baseline etag in memory and on-disk sidecar.
	if _, err := c.Fetch(t.Context()); err != nil {
		t.Fatalf("seed Fetch: %v", err)
	}
	hitsAfterSeed := fs.hits.Load()

	// Simulate a peer mid-download: hold .tmp.
	if err := os.WriteFile(path+".tmp", []byte("partial"), 0o600); err != nil {
		t.Fatalf("seed tmp: %v", err)
	}
	// Simulate peer having just installed a new sidecar (different etag).
	if err := os.WriteFile(path+".meta", []byte(`{"etag":"\"peer-new\"","last_modified":"Tue, 03 Jan 2006 15:04:05 GMT"}`), 0o600); err != nil {
		t.Fatalf("seed meta: %v", err)
	}

	updated, err := c.Fetch(t.Context())
	if !errors.Is(err, httpcache.ErrPeerFetching) {
		t.Errorf("err = %v, want ErrPeerFetching", err)
	}
	if !updated {
		t.Error("expected updated=true (peer wrote new sidecar)")
	}
	if got := fs.hits.Load(); got != hitsAfterSeed {
		t.Errorf("server hits = %d, want %d (must not fetch when peer holds tmp)", got, hitsAfterSeed)
	}
}

func TestCacher_MaxBytesAtLimit(t *testing.T) {
	body := []byte("0123456789ABCDEF") // 16 bytes
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(body)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.MaxBytes = int64(len(body)) // exactly equal — should pass
	if _, err := c.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	got, _ := os.ReadFile(path)
	if string(got) != string(body) {
		t.Errorf("body = %q, want %q", got, body)
	}
}

func TestCacher_FailureBackoff(t *testing.T) {
	fs := &fakeServer{body: []byte("body"), etag: `"e1"`}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Fail the first request only; let later ones through.
		if fs.hits.Add(1) == 1 {
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		if r.Header.Get("If-None-Match") == fs.etag {
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("ETag", fs.etag)
		w.Header().Set("Last-Modified", "Mon, 02 Jan 2006 15:04:05 GMT")
		_, _ = w.Write(fs.body)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.FailureBackoff = time.Hour

	// First Fetch fails with 429 and records the failure time.
	if _, err := c.Fetch(t.Context()); err == nil {
		t.Fatal("first Fetch: expected error")
	}

	// The immediate retry must not reach the wire.
	if updated, err := c.Fetch(t.Context()); err != nil || updated {
		t.Fatalf("retry: updated=%v err=%v, want false/nil (backoff gate)", updated, err)
	}
	if got := fs.hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (failed fetch must be gated)", got)
	}

	// After the backoff expires (sidecar rewritten with an old failure
	// time, loaded by a fresh Cacher), the retry reaches the wire and
	// succeeds.
	expired := fmt.Sprintf(`{"failed_at":%d}`, time.Now().Add(-time.Hour).UnixMilli())
	if err := os.WriteFile(path+".meta", []byte(expired), 0o600); err != nil {
		t.Fatalf("expire failure: %v", err)
	}
	fresh := httpcache.New(srv.URL, path)
	fresh.FailureBackoff = time.Hour
	updated, err := fresh.Fetch(t.Context())
	if err != nil {
		t.Fatalf("retry after backoff: %v", err)
	}
	if !updated {
		t.Error("retry after backoff: expected updated=true")
	}
	if got := fs.hits.Load(); got != 2 {
		t.Errorf("server hits = %d, want 2", got)
	}

	// A successful fetch clears the failure state from the sidecar.
	var meta map[string]any
	data, err := os.ReadFile(path + ".meta")
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("parse sidecar: %v", err)
	}
	if _, ok := meta["failed_at"]; ok {
		t.Errorf("failed_at = %v, want cleared after success", meta["failed_at"])
	}
}

func TestCacher_FailureBackoffDefaultsToMaxAge(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.MaxAge = time.Hour // FailureBackoff unset → failures wait MaxAge

	if _, err := c.Fetch(t.Context()); err == nil {
		t.Fatal("first Fetch: expected error")
	}
	if updated, err := c.Fetch(t.Context()); err != nil || updated {
		t.Fatalf("retry: updated=%v err=%v, want gated", updated, err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (backoff must default to MaxAge)", got)
	}
}

func TestCacher_FailureBackoffPersistsAcrossInstances(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.FailureBackoff = time.Hour
	if _, err := c.Fetch(t.Context()); err == nil {
		t.Fatal("first Fetch: expected failure")
	}

	// A brand-new Cacher (simulated process restart) must honor the
	// recorded failure without a single HTTP request.
	fresh := httpcache.New(srv.URL, path)
	fresh.FailureBackoff = time.Hour
	if updated, err := fresh.Fetch(t.Context()); err != nil || updated {
		t.Fatalf("fresh Fetch: updated=%v err=%v, want gated", updated, err)
	}
	if got := hits.Load(); got != 1 {
		t.Errorf("server hits = %d, want 1 (backoff must survive restart)", got)
	}
}

func TestCacher_304ClearsFailure(t *testing.T) {
	fs := &fakeServer{body: []byte("body"), etag: `"e1"`}
	srv := httptest.NewServer(http.HandlerFunc(fs.handler))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.FailureBackoff = time.Hour
	if _, err := c.Fetch(t.Context()); err != nil {
		t.Fatalf("seed Fetch: %v", err)
	}

	// Hand-write a failure into the sidecar (epoch-time, so the gate
	// is already expired) with the known-good ETag, then use a FRESH
	// Cacher so the sidecar is actually loaded (metaLoaded=false).
	sidecar := `{"etag":"\"e1\"","last_modified":"Mon, 02 Jan 2006 15:04:05 GMT","failed_at":1}`
	if err := os.WriteFile(path+".meta", []byte(sidecar), 0o600); err != nil {
		t.Fatalf("seed sidecar: %v", err)
	}
	fresh := httpcache.New(srv.URL, path)
	fresh.FailureBackoff = time.Hour

	// The conditional GET gets a 304 — the remote proved healthy, so
	// the failure state must be cleared.
	updated, err := fresh.Fetch(t.Context())
	if err != nil || updated {
		t.Fatalf("Fetch: updated=%v err=%v, want false/nil (304)", updated, err)
	}
	data, err := os.ReadFile(path + ".meta")
	if err != nil {
		t.Fatalf("read sidecar: %v", err)
	}
	var meta map[string]any
	if err := json.Unmarshal(data, &meta); err != nil {
		t.Fatalf("parse sidecar: %v", err)
	}
	if _, ok := meta["failed_at"]; ok {
		t.Errorf("failed_at = %v, want cleared by 304", meta["failed_at"])
	}
}

func TestCacher_ContextCanceledNotBackedOff(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) > 1 {
			w.Header().Set("ETag", `"e1"`)
			_, _ = w.Write([]byte("body"))
			return
		}
		<-r.Context().Done() // hang until the client gives up
	}))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	c.FailureBackoff = time.Hour

	ctx, cancel := context.WithCancel(t.Context())
	errCh := make(chan error, 1)
	go func() {
		_, err := c.Fetch(ctx)
		errCh <- err
	}()
	time.Sleep(50 * time.Millisecond) // let the request reach the server
	cancel()
	if err := <-errCh; err == nil {
		t.Fatal("expected context error from canceled Fetch")
	}

	// A canceled fetch is not an upstream failure: the next Fetch must
	// go back to the wire immediately, not wait out the backoff.
	if updated, err := c.Fetch(t.Context()); err != nil {
		t.Fatalf("Fetch after cancel: %v", err)
	} else if !updated {
		t.Error("Fetch after cancel: expected updated=true")
	}
	if got := hits.Load(); got != 2 {
		t.Errorf("server hits = %d, want 2 (canceled fetch must not gate)", got)
	}
}

func TestBasicAuth(t *testing.T) {
	// base64("user:pass") == "dXNlcjpwYXNz"
	if got, want := httpcache.BasicAuth("user", "pass"), "Basic dXNlcjpwYXNz"; got != want {
		t.Errorf("BasicAuth = %q, want %q", got, want)
	}
}

func TestBearer(t *testing.T) {
	if got, want := httpcache.Bearer("tok"), "Bearer tok"; got != want {
		t.Errorf("Bearer = %q, want %q", got, want)
	}
}
