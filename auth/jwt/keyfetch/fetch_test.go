package keyfetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// testJWKS generates a fresh Ed25519 key and returns the public key plus the
// serialized JWKS document bytes.
func testJWKS(t *testing.T) (jwt.PublicKey, []byte) {
	t.Helper()
	priv, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey: %v", err)
	}
	pub, err := priv.PublicKey()
	if err != nil {
		t.Fatalf("PublicKey: %v", err)
	}
	jwks := jwt.WellKnownJWKs{Keys: []jwt.PublicKey{*pub}}
	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}
	return *pub, data
}

// --- FetchURL tests ---

func TestFetchURL_Success(t *testing.T) {
	pub, jwksData := testJWKS(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"test-etag"`)
		w.Header().Set("Cache-Control", "max-age=300")
		w.Write(jwksData)
	}))
	defer srv.Close()

	keys, resp, err := FetchURL(context.Background(), srv.URL, nil)
	if err != nil {
		t.Fatalf("FetchURL: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KID != pub.KID {
		t.Errorf("KID mismatch: got %q, want %q", keys[0].KID, pub.KID)
	}
	if resp == nil {
		t.Fatal("expected non-nil response")
	}
	if got := resp.Header.Get("ETag"); got != `"test-etag"` {
		t.Errorf("ETag header: got %q, want %q", got, `"test-etag"`)
	}
}

func TestFetchURL_404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.NotFound(w, r)
	}))
	defer srv.Close()

	_, _, err := FetchURL(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatal("expected error for 404")
	}
	if !errorContains(err, ErrFetchFailed) {
		t.Errorf("expected ErrFetchFailed, got: %v", err)
	}
}

func TestFetchURL_500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	_, _, err := FetchURL(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatal("expected error for 500")
	}
	if !errorContains(err, ErrFetchFailed) {
		t.Errorf("expected ErrFetchFailed, got: %v", err)
	}
}

func TestFetchURL_MalformedJSON(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{not valid json`))
	}))
	defer srv.Close()

	_, _, err := FetchURL(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatal("expected error for malformed JSON")
	}
	if !errorContains(err, ErrFetchFailed) {
		t.Errorf("expected ErrFetchFailed, got: %v", err)
	}
}

func TestFetchURL_EmptyJWKS(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"keys":[]}`))
	}))
	defer srv.Close()

	_, _, err := FetchURL(context.Background(), srv.URL, nil)
	if err == nil {
		t.Fatal("expected error for empty JWKS")
	}
	if !errors.Is(err, ErrEmptyKeySet) {
		t.Errorf("expected ErrEmptyKeySet, got: %v", err)
	}
}

// --- FetchOIDC tests ---

func TestFetchOIDC_Success(t *testing.T) {
	_, jwksData := testJWKS(t)

	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			doc := fmt.Sprintf(`{"jwks_uri": "%s/jwks.json"}`, srvURL)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(doc))
		case "/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	keys, _, err := FetchOIDC(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("FetchOIDC: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

// srv is declared at function scope above; this variable name is fine in a
// separate test function.

func TestFetchOIDC_NonHTTPSJwksURI(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Return a jwks_uri with http:// instead of https://
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"jwks_uri": "http://example.com/jwks.json"}`))
	}))
	defer srv.Close()

	_, _, err := FetchOIDC(context.Background(), srv.URL, srv.Client())
	if err == nil {
		t.Fatal("expected error for non-https jwks_uri")
	}
	if !errorContains(err, ErrFetchFailed) {
		t.Errorf("expected ErrFetchFailed, got: %v", err)
	}
}

// --- FetchOAuth2 tests ---

func TestFetchOAuth2_Success(t *testing.T) {
	_, jwksData := testJWKS(t)

	var srvURL string
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/.well-known/oauth-authorization-server":
			doc := fmt.Sprintf(`{"jwks_uri": "%s/jwks.json"}`, srvURL)
			w.Header().Set("Content-Type", "application/json")
			w.Write([]byte(doc))
		case "/jwks.json":
			w.Header().Set("Content-Type", "application/json")
			w.Write(jwksData)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	srvURL = srv.URL

	keys, _, err := FetchOAuth2(context.Background(), srv.URL, srv.Client())
	if err != nil {
		t.Fatalf("FetchOAuth2: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
}

// --- KeyFetcher.Verifier() tests ---

func TestKeyFetcher_Verifier_CachesResult(t *testing.T) {
	_, jwksData := testJWKS(t)

	var fetchCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fetchCount++
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write(jwksData)
	}))
	defer srv.Close()

	kf := &KeyFetcher{URL: srv.URL}

	// First call fetches
	v1, err := kf.Verifier()
	if err != nil {
		t.Fatalf("first Verifier call: %v", err)
	}
	if v1 == nil {
		t.Fatal("expected non-nil verifier")
	}
	if fetchCount != 1 {
		t.Fatalf("expected 1 fetch, got %d", fetchCount)
	}

	// Second call returns cached (within TTL)
	v2, err := kf.Verifier()
	if err != nil {
		t.Fatalf("second Verifier call: %v", err)
	}
	if v2 != v1 {
		t.Error("expected same verifier instance from cache")
	}
	if fetchCount != 1 {
		t.Errorf("expected still 1 fetch, got %d", fetchCount)
	}
}

func TestKeyFetcher_Verifier_InitialKeys(t *testing.T) {
	pub, jwksData := testJWKS(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write(jwksData)
	}))
	defer srv.Close()

	kf := &KeyFetcher{
		URL:            srv.URL,
		InitialKeys:    []jwt.PublicKey{pub},
		RefreshTimeout: 5 * time.Second,
	}

	// First call should return immediately with initial keys (they are
	// marked expired, but RefreshTimeout lets them be served while refresh
	// runs in background).
	v, err := kf.Verifier()
	if err != nil && !errorContains(err, ErrKeysExpired) {
		t.Fatalf("first Verifier call: %v", err)
	}
	if v == nil {
		t.Fatal("expected non-nil verifier from InitialKeys")
	}

	// Wait for background refresh to complete
	time.Sleep(500 * time.Millisecond)

	// Now should have fresh keys
	v2, err := kf.Verifier()
	if err != nil {
		t.Fatalf("second Verifier call after refresh: %v", err)
	}
	if v2 == nil {
		t.Fatal("expected non-nil verifier after refresh")
	}
}

func TestKeyFetcher_RefreshedAt(t *testing.T) {
	_, jwksData := testJWKS(t)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Cache-Control", "max-age=3600")
		w.Write(jwksData)
	}))
	defer srv.Close()

	kf := &KeyFetcher{URL: srv.URL}

	// Before any fetch
	if !kf.RefreshedAt().IsZero() {
		t.Error("RefreshedAt should be zero before first fetch")
	}

	before := time.Now()
	_, err := kf.Verifier()
	if err != nil {
		t.Fatalf("Verifier: %v", err)
	}
	after := time.Now()

	rat := kf.RefreshedAt()
	if rat.Before(before) || rat.After(after) {
		t.Errorf("RefreshedAt %v not between %v and %v", rat, before, after)
	}
}

// --- cacheTimings tests ---

func TestCacheTimings_MaxAge(t *testing.T) {
	now := time.Now()
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Cache-Control", "max-age=600")
	p := defaultPolicy()

	expiry, stale := cacheTimings(now, resp, p)

	wantExpiry := now.Add(600 * time.Second)
	wantStale := now.Add(600 * time.Second * 3 / 4)

	if !timesClose(expiry, wantExpiry, time.Second) {
		t.Errorf("expiry: got %v, want ~%v", expiry, wantExpiry)
	}
	if !timesClose(stale, wantStale, time.Second) {
		t.Errorf("stale: got %v, want ~%v", stale, wantStale)
	}
}

func TestCacheTimings_NoHeaders(t *testing.T) {
	now := time.Now()
	resp := &http.Response{Header: http.Header{}}
	p := defaultPolicy()

	expiry, stale := cacheTimings(now, resp, p)

	wantExpiry := now.Add(defaultTTL)
	wantStale := now.Add(defaultTTL * 3 / 4)

	if !timesClose(expiry, wantExpiry, time.Second) {
		t.Errorf("expiry: got %v, want ~%v", expiry, wantExpiry)
	}
	if !timesClose(stale, wantStale, time.Second) {
		t.Errorf("stale: got %v, want ~%v", stale, wantStale)
	}
}

func TestCacheTimings_BelowMinTTL(t *testing.T) {
	now := time.Now()
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Cache-Control", "max-age=5") // 5s < 1m minTTL
	p := defaultPolicy()

	expiry, stale := cacheTimings(now, resp, p)

	// Below min: expiry = minTTL*2, stale = minTTL
	wantExpiry := now.Add(p.minTTL * 2)
	wantStale := now.Add(p.minTTL)

	if !timesClose(expiry, wantExpiry, time.Second) {
		t.Errorf("expiry: got %v, want ~%v", expiry, wantExpiry)
	}
	if !timesClose(stale, wantStale, time.Second) {
		t.Errorf("stale: got %v, want ~%v", stale, wantStale)
	}
}

func TestCacheTimings_AboveMaxTTL(t *testing.T) {
	now := time.Now()
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Cache-Control", "max-age=200000") // ~55h > 24h maxTTL
	p := defaultPolicy()

	expiry, stale := cacheTimings(now, resp, p)

	wantExpiry := now.Add(p.maxTTL)
	wantStale := now.Add(p.maxTTL * 3 / 4)

	if !timesClose(expiry, wantExpiry, time.Second) {
		t.Errorf("expiry: got %v, want ~%v", expiry, wantExpiry)
	}
	if !timesClose(stale, wantStale, time.Second) {
		t.Errorf("stale: got %v, want ~%v", stale, wantStale)
	}
}

func TestCacheTimings_AgeHeader(t *testing.T) {
	now := time.Now()
	resp := &http.Response{Header: http.Header{}}
	resp.Header.Set("Cache-Control", "max-age=600")
	resp.Header.Set("Age", "100")
	p := defaultPolicy()

	expiry, stale := cacheTimings(now, resp, p)

	// Effective TTL = 600 - 100 = 500s
	wantExpiry := now.Add(500 * time.Second)
	wantStale := now.Add(500 * time.Second * 3 / 4)

	if !timesClose(expiry, wantExpiry, time.Second) {
		t.Errorf("expiry: got %v, want ~%v", expiry, wantExpiry)
	}
	if !timesClose(stale, wantStale, time.Second) {
		t.Errorf("stale: got %v, want ~%v", stale, wantStale)
	}
}

// --- Conditional request (304) tests ---

func TestConditionalRequest_304(t *testing.T) {
	_, jwksData := testJWKS(t)

	var requestCount int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount++
		if r.Header.Get("If-None-Match") == `"test-etag"` {
			w.Header().Set("Cache-Control", "max-age=600")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("ETag", `"test-etag"`)
		w.Header().Set("Cache-Control", "max-age=600")
		w.Write(jwksData)
	}))
	defer srv.Close()

	p := defaultPolicy()

	// First fetch: gets full body
	a1, resp1, err := fetchRaw(context.Background(), srv.URL, nil, p, nil)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if resp1.StatusCode != http.StatusOK {
		t.Fatalf("first fetch status: got %d, want 200", resp1.StatusCode)
	}
	if a1.etag != `"test-etag"` {
		t.Errorf("etag not captured: got %q", a1.etag)
	}

	// Second fetch with prev: should get 304
	a2, resp2, err := fetchRaw(context.Background(), srv.URL, nil, p, a1)
	if err != nil {
		t.Fatalf("conditional fetch: %v", err)
	}
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional fetch status: got %d, want 304", resp2.StatusCode)
	}

	// Body should be reused from prev
	if string(a2.data) != string(a1.data) {
		t.Error("304 response did not reuse previous body")
	}

	// Cache timing should be refreshed
	if a2.expiry.Equal(a1.expiry) {
		t.Error("304 response should have refreshed expiry")
	}

	if requestCount != 2 {
		t.Errorf("expected 2 requests, got %d", requestCount)
	}
}

func TestConditionalRequest_LastModified(t *testing.T) {
	_, jwksData := testJWKS(t)

	lastMod := "Wed, 01 Jan 2025 00:00:00 GMT"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("If-Modified-Since") == lastMod {
			w.Header().Set("Cache-Control", "max-age=600")
			w.WriteHeader(http.StatusNotModified)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Last-Modified", lastMod)
		w.Header().Set("Cache-Control", "max-age=600")
		w.Write(jwksData)
	}))
	defer srv.Close()

	p := defaultPolicy()

	a1, _, err := fetchRaw(context.Background(), srv.URL, nil, p, nil)
	if err != nil {
		t.Fatalf("first fetch: %v", err)
	}
	if a1.lastModified != lastMod {
		t.Errorf("lastModified not captured: got %q", a1.lastModified)
	}

	a2, resp2, err := fetchRaw(context.Background(), srv.URL, nil, p, a1)
	if err != nil {
		t.Fatalf("conditional fetch: %v", err)
	}
	if resp2.StatusCode != http.StatusNotModified {
		t.Fatalf("conditional fetch status: got %d, want 304", resp2.StatusCode)
	}
	if string(a2.data) != string(a1.data) {
		t.Error("304 response did not reuse previous body")
	}
}

// --- parseCacheControlMaxAge tests ---

func TestParseCacheControlMaxAge(t *testing.T) {
	tests := []struct {
		header string
		want   time.Duration
	}{
		{"max-age=300", 300 * time.Second},
		{"public, max-age=600", 600 * time.Second},
		{"max-age=0", 0},
		{"no-cache", 0},
		{"", 0},
		{"max-age=abc", 0},
		{"max-age=-1", 0},
	}
	for _, tt := range tests {
		got := parseCacheControlMaxAge(tt.header)
		if got != tt.want {
			t.Errorf("parseCacheControlMaxAge(%q) = %v, want %v", tt.header, got, tt.want)
		}
	}
}

// --- parseAge tests ---

func TestParseAge(t *testing.T) {
	tests := []struct {
		header string
		want   time.Duration
	}{
		{"100", 100 * time.Second},
		{"0", 0},
		{"-5", 0},
		{"", 0},
		{"abc", 0},
	}
	for _, tt := range tests {
		got := parseAge(tt.header)
		if got != tt.want {
			t.Errorf("parseAge(%q) = %v, want %v", tt.header, got, tt.want)
		}
	}
}

// --- helpers ---

func errorContains(err, target error) bool {
	return errors.Is(err, target)
}

func timesClose(a, b time.Time, tolerance time.Duration) bool {
	diff := a.Sub(b)
	if diff < 0 {
		diff = -diff
	}
	return diff <= tolerance
}
