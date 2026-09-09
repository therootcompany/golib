package geoip

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// writeConf writes a minimal GeoIP.conf with the given edition IDs to dir.
func writeConf(t *testing.T, dir string, editions ...string) string {
	t.Helper()
	conf := "AccountID   123456\nLicenseKey  testkey\nEditionIDs  " +
		joinSpace(editions) + "\n"
	p := filepath.Join(dir, "GeoIP.conf")
	if err := os.WriteFile(p, []byte(conf), 0o600); err != nil {
		t.Fatalf("write conf: %v", err)
	}
	return p
}

func joinSpace(ss []string) string {
	var s strings.Builder
	for i, x := range ss {
		if i > 0 {
			s.WriteString(" ")
		}
		s.WriteString(x)
	}
	return s.String()
}

// TestFetcherDownloadAuth verifies the first fetch issues a Basic-auth GET,
// writes the tarball to disk, and reports updated=true. A second fetch within
// MaxAge skips HTTP entirely (server hit count stays at 1).
func TestFetcherDownloadAuth(t *testing.T) {
	const (
		user = "123456"
		key  = "testkey"
	)
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		got := r.Header.Get("Authorization")
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte(user+":"+key))
		if got != want {
			http.Error(w, "bad auth", http.StatusUnauthorized)
			return
		}
		if r.URL.Path != "/GeoLite2-City/download" {
			http.Error(w, "bad path "+r.URL.Path, http.StatusBadRequest)
			return
		}
		w.Header().Set("ETag", `"v1"`)
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TARGZ-BODY-CITY"))
	}))
	defer srv.Close()

	dir := t.TempDir()
	confPath := writeConf(t, dir, "GeoLite2-City")

	f, err := NewFetcher(confPath)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	f.Dir = dir
	f.BaseURL = srv.URL
	f.HTTPClient = srv.Client()

	updated, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch #1: %v", err)
	}
	if !updated {
		t.Fatal("Fetch #1: expected updated=true")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("Fetch #1: server hits = %d, want 1", got)
	}
	if _, err := os.Stat(filepath.Join(dir, TarGzName("GeoLite2-City"))); err != nil {
		t.Fatalf("tarball not written: %v", err)
	}

	// Second fetch within MaxAge (default 3 days) should skip HTTP.
	updated, err = f.Fetch(context.Background())
	if err != nil {
		t.Fatalf("Fetch #2: %v", err)
	}
	if updated {
		t.Fatal("Fetch #2: expected updated=false within MaxAge")
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("Fetch #2: server hits = %d, want 1 (MaxAge gate)", got)
	}
}

// TestFetcherConditionalGET verifies the conditional-GET flow: a stale local
// file triggers an If-None-Match GET. A 304 reports updated=false; a 200 with
// a new ETag reports updated=true and rewrites the file.
func TestFetcherConditionalGET(t *testing.T) {
	var hits, condHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		switch r.Header.Get("If-None-Match") {
		case `"v1"`:
			// First conditional request: not modified.
			if atomic.AddInt32(&condHits, 1) == 1 {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			// Server changed its mind: ship v2.
			w.Header().Set("ETag", `"v2"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("TARGZ-CITY-V2"))
		default:
			// Prime: offer v1.
			w.Header().Set("ETag", `"v1"`)
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("TARGZ-CITY-V1"))
		}
	}))
	defer srv.Close()

	dir := t.TempDir()
	confPath := writeConf(t, dir, "GeoLite2-City")

	f, err := NewFetcher(confPath)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	f.Dir = dir
	f.BaseURL = srv.URL
	f.HTTPClient = srv.Client()

	// Prime with v1.
	if updated, err := f.Fetch(context.Background()); err != nil || !updated {
		t.Fatalf("prime: updated=%v err=%v", updated, err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("prime hits = %d, want 1", got)
	}

	// Backdate the local file so MaxAge no longer gates the next fetch.
	p := filepath.Join(dir, TarGzName("GeoLite2-City"))
	old := time.Now().Add(-4 * 24 * time.Hour)
	if err := os.Chtimes(p, old, old); err != nil {
		t.Fatalf("Chtimes: %v", err)
	}

	// Server now returns 304 (not modified) for the conditional request.
	if updated, err := f.Fetch(context.Background()); err != nil || updated {
		t.Fatalf("304 path: updated=%v err=%v", updated, err)
	}
	if got := atomic.LoadInt32(&hits); got != 2 {
		t.Fatalf("after 304 hits = %d, want 2", got)
	}

	// Server now returns 200 with the new body/ETag.
	if updated, err := f.Fetch(context.Background()); err != nil || !updated {
		t.Fatalf("200 path: updated=%v err=%v", updated, err)
	}
	if got := atomic.LoadInt32(&hits); got != 3 {
		t.Fatalf("after 200 hits = %d, want 3", got)
	}
	b, _ := os.ReadFile(p)
	if string(b) != "TARGZ-CITY-V2" {
		t.Fatalf("body = %q, want TARGZ-CITY-V2", string(b))
	}
}

// TestFetcherDefaultFreshDays ensures a zero FreshDays defaults to a 3-day
// MaxAge gate.
func TestFetcherDefaultFreshDays(t *testing.T) {
	dir := t.TempDir()
	confPath := writeConf(t, dir, "GeoLite2-City")
	f, err := NewFetcher(confPath)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	if err := f.ready(); err != nil {
		t.Fatalf("ready: %v", err)
	}
	if want := 3 * 24 * time.Hour; f.maxAge != want {
		t.Fatalf("maxAge = %v, want %v", f.maxAge, want)
	}
	if len(f.cachers) != 1 {
		t.Fatalf("cachers = %d, want 1", len(f.cachers))
	}
}

// TestFetcherExplicitFreshDays checks a non-default FreshDays is applied.
func TestFetcherExplicitFreshDays(t *testing.T) {
	dir := t.TempDir()
	confPath := writeConf(t, dir, "GeoLite2-City")
	f, err := NewFetcher(confPath)
	if err != nil {
		t.Fatalf("NewFetcher: %v", err)
	}
	f.FreshDays = 10
	if err := f.ready(); err != nil {
		t.Fatalf("ready: %v", err)
	}
	if want := 10 * 24 * time.Hour; f.maxAge != want {
		t.Fatalf("maxAge = %v, want %v", f.maxAge, want)
	}
}

// TestFetcherMissingConf ensures a missing conf file returns an error.
func TestFetcherMissingConf(t *testing.T) {
	if _, err := NewFetcher(filepath.Join(t.TempDir(), "nope.conf")); err == nil {
		t.Fatal("expected error for missing conf")
	}
}
