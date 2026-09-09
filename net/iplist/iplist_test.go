package iplist

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestParseTSV(t *testing.T) {
	got, err := Parse(strings.NewReader("network\tnote\n# comment\n192.0.2.1\tlocal\nexample.com\n"))
	if err != nil || len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "example.com" {
		t.Fatalf("entries=%#v err=%v", got, err)
	}
}

func TestLoadWithClient(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.7\n"))
	}))
	defer server.Close()

	called := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return http.DefaultTransport.RoundTrip(r)
	})}
	entries, err := LoadWithClient(context.Background(), server.URL, t.TempDir(), client)
	if err != nil {
		t.Fatal(err)
	}
	if !called || len(entries) != 1 || entries[0] != "192.0.2.7" {
		t.Fatalf("called=%v entries=%#v", called, entries)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func TestLoadURLAuthCacheAndNested(t *testing.T) {
	var authOK bool
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("192.0.2.2\n")) }))
	defer inner.Close()
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authOK = r.Header.Get("Authorization") == "Basic dTpw"
		_, _ = w.Write([]byte("network\n" + inner.URL + "\n"))
	}))
	defer outer.Close()

	cacheDir := t.TempDir()
	got, err := Load(context.Background(), strings.Replace(outer.URL, "http://", "http://u:p@", 1), cacheDir)
	if err != nil || !authOK || len(got) != 1 || got[0] != "192.0.2.2" {
		t.Fatalf("auth=%v entries=%#v err=%v", authOK, got, err)
	}
	matches, err := filepath.Glob(filepath.Join(cacheDir, "ip-sources", "*.tsv"))
	if err != nil || len(matches) != 2 {
		t.Fatalf("cache files=%v err=%v", matches, err)
	}
	if _, err := os.Stat(matches[0] + ".meta"); err != nil {
		t.Fatal(err)
	}
}
