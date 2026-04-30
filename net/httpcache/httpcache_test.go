package httpcache_test

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"

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

	updated, err := c.Fetch()
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
	if _, err := c.Fetch(); err != nil {
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
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("first Fetch: %v", err)
	}

	updated, err := c.Fetch()
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
	if _, err := httpcache.New(srv.URL, path).Fetch(); err != nil {
		t.Fatalf("seed Fetch: %v", err)
	}

	fresh := httpcache.New(srv.URL, path)
	updated, err := fresh.Fetch()
	if err != nil {
		t.Fatalf("fresh Fetch: %v", err)
	}
	if updated {
		t.Error("fresh Fetch: expected updated=false (sidecar should have provided ETag)")
	}
}

func TestCacher_BodyChanges_Redownloads(t *testing.T) {
	fs := &fakeServer{body: []byte("v1"), etag: `"v1"`}
	srv := httptest.NewServer(http.HandlerFunc(fs.handler))
	defer srv.Close()

	path := filepath.Join(t.TempDir(), "data.txt")
	c := httpcache.New(srv.URL, path)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("initial Fetch: %v", err)
	}

	fs.body = []byte("v2-longer-body")
	fs.etag = `"v2"`

	updated, err := c.Fetch()
	if err != nil {
		t.Fatalf("re-Fetch: %v", err)
	}
	if !updated {
		t.Error("expected updated=true after server-side change")
	}
	got, _ := os.ReadFile(path)
	if string(got) != "v2-longer-body" {
		t.Errorf("body = %q, want v2-longer-body", got)
	}
}

func TestCacher_UnexpectedStatus(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "nope", http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := httpcache.New(srv.URL, filepath.Join(t.TempDir(), "data.txt"))
	_, err := c.Fetch()
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
	_, err := c.Fetch()
	if !errors.Is(err, httpcache.ErrEmptyResponse) {
		t.Errorf("err = %v, want ErrEmptyResponse", err)
	}
}

func TestCacher_AuthHeaderStrippedOnRedirect(t *testing.T) {
	// Final hop should not see Authorization. Initial hop should.
	var initialAuth, finalAuth string
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		finalAuth = r.Header.Get("Authorization")
		_, _ = w.Write([]byte("ok"))
	}))
	defer final.Close()
	first := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		initialAuth = r.Header.Get("Authorization")
		http.Redirect(w, r, final.URL, http.StatusFound)
	}))
	defer first.Close()

	c := httpcache.New(first.URL, filepath.Join(t.TempDir(), "data.txt"))
	c.Header = http.Header{"Authorization": []string{"Bearer secret-token"}}
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("Fetch: %v", err)
	}
	if initialAuth != "Bearer secret-token" {
		t.Errorf("initial Authorization = %q, want Bearer secret-token", initialAuth)
	}
	if finalAuth != "" {
		t.Errorf("final Authorization = %q, want empty (must be stripped on redirect)", finalAuth)
	}
}
