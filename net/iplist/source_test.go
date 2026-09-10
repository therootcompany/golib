package iplist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestCurrentZeroAlloc(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.tsv")
	var body []byte
	for i := range 1000 {
		body = append(body, []byte("10.0.0.")...)
		body = append(body, '0'+byte(i%10))
		body = append(body, '\n')
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := NewIPList(t.Context(), IPListConfig{Source: path, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer s.Stop()

	_ = s.Current() // warm up

	allocs := testing.AllocsPerRun(100, func() {
		_ = s.Current()
	})
	if allocs != 0 {
		t.Errorf("Current() allocs per call = %.1f, want 0 (hot path must be zero-alloc)", allocs)
	}
}

func TestSourceKeepsLastGoodEntriesAfterFailedRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewIPList(t.Context(), IPListConfig{Source: path, CacheDir: t.TempDir()})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Stop()

	if got := source.Current(); got == nil || len(*got) != 1 || (*got)[0] != "192.0.2.1" {
		t.Fatalf("initial entries = %#v", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	source.config.RefreshInterval = 0
	if _, err := source.Load(t.Context(), true); err == nil {
		t.Fatal("invalid refresh unexpectedly succeeded")
	}
	if got := source.Current(); got == nil || len(*got) != 1 || (*got)[0] != "192.0.2.1" {
		t.Fatalf("entries after failed refresh = %#v", got)
	}
}

func TestSourceOptionalMissingFileIsEmpty(t *testing.T) {
	source, err := NewIPList(t.Context(), IPListConfig{
		Source:   filepath.Join(t.TempDir(), "missing.tsv"),
		CacheDir: t.TempDir(),
		Optional: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer source.Stop()
	if got := source.Current(); got == nil || len(*got) != 0 {
		t.Fatalf("entries = %#v", got)
	}
}
