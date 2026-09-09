package iplist

import (
	"os"
	"path/filepath"
	"testing"
)

func TestSourceKeepsLastGoodEntriesAfterFailedRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "list.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	source, err := NewSource(t.Context(), SourceConfig{Source: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()

	if got := source.Entries(); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("initial entries = %#v", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := source.Refresh(); err == nil {
		t.Fatal("invalid refresh unexpectedly succeeded")
	}
	if got := source.Entries(); len(got) != 1 || got[0] != "192.0.2.1" {
		t.Fatalf("entries after failed refresh = %#v", got)
	}
}

func TestSourceOptionalMissingFileIsEmpty(t *testing.T) {
	source, err := NewSource(t.Context(), SourceConfig{
		Source:   filepath.Join(t.TempDir(), "missing.tsv"),
		Optional: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = source.Close() }()
	if got := source.Entries(); len(got) != 0 {
		t.Fatalf("entries = %#v", got)
	}
}
