package iplist

import (
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

func TestParseCSV(t *testing.T) {
	got, err := Parse(strings.NewReader("network,note\n# comment\n192.0.2.1,local\nexample.com\n"))
	if err != nil || len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "example.com" {
		t.Fatalf("entries=%#v err=%v", got, err)
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		entry string
		want  bool
	}{
		{"192.0.2.1", true},
		{"2001:db8::1", true},
		{"10.0.0.0/8", true},
		{"2001:db8::/32", true},
		{"example.com", true},
		{"sub.example.com", true},
		{"", false},
		{"not valid", false},
		{"has space.com", false},
		{"/missing/domain", false},
		{"http://example.com", false}, // URLs are not valid entries
	}

	for _, tt := range tests {
		if got := Validate(tt.entry); got != tt.want {
			t.Errorf("Validate(%q) = %v, want %v", tt.entry, got, tt.want)
		}
	}
}

func TestLoadRejectsInvalidEntry(t *testing.T) {
	dir := t.TempDir()
	// Write a local file with an invalid entry.
	path := filepath.Join(dir, "bad.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\nnot valid entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Load(t.Context(), path, dir, nil)
	if err == nil {
		t.Fatal("expected error for invalid entry, got nil")
	}
}

func TestLoadCustomClient(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.7\n"))
	}))
	defer srv.Close()

	called := false
	client := &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		called = true
		return http.DefaultTransport.RoundTrip(r)
	})}
	entries, err := Load(t.Context(), srv.URL, t.TempDir(), client)
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
	inner := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("192.0.2.2\n"))
	}))
	defer inner.Close()
	outer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		authOK = r.Header.Get("Authorization") == "Basic dTpw"
		_, _ = w.Write([]byte("network\n" + inner.URL + "\n"))
	}))
	defer outer.Close()

	cacheDir := t.TempDir()
	got, err := Load(t.Context(), strings.Replace(outer.URL, "http://", "http://u:p@", 1), cacheDir, nil)
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

func TestLoadAcceptHeader(t *testing.T) {
	var acceptOK bool
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		acceptOK = strings.Contains(r.Header.Get("Accept"), "text/tab-separated-values")
		_, _ = w.Write([]byte("192.0.2.1\n"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	if _, err := Load(t.Context(), srv.URL, cacheDir, nil); err != nil {
		t.Fatal(err)
	}
	if !acceptOK {
		t.Fatal("expected Accept header to contain text/tab-separated-values")
	}
}

func TestLoadCSVDetection(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/csv")
		_, _ = w.Write([]byte("network,note\n192.0.2.1,local\n10.0.0.0/8,internal\n"))
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	got, err := Load(t.Context(), srv.URL, cacheDir, nil)
	if err != nil {
		t.Fatalf("err=%v", err)
	}
	if len(got) != 2 || got[0] != "192.0.2.1" || got[1] != "10.0.0.0/8" {
		t.Fatalf("entries=%#v", got)
	}
}
