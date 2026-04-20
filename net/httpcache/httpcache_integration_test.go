//go:build integration

package httpcache_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/therootcompany/golib/net/httpcache"
)

const (
	testURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/single_ips.txt"
	testFile = "httpcache_inbound.txt"
)

func testdataDir(t *testing.T) string {
	t.Helper()
	dir, _ := filepath.Abs(".")
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return filepath.Join(dir, "testdata")
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("could not find module root (go.mod)")
		}
		dir = parent
	}
}

func TestCacher_Download(t *testing.T) {
	path := filepath.Join(testdataDir(t), testFile)
	os.Remove(path) // start fresh

	c := httpcache.New(testURL, path)

	updated, err := c.Fetch()
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}
	if !updated {
		t.Error("first Fetch: expected updated=true")
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("file not created: %v", err)
	}
	if info.Size() == 0 {
		t.Error("downloaded file is empty")
	}
	t.Logf("downloaded %d bytes to %s", info.Size(), path)
}

func TestCacher_ConditionalGet(t *testing.T) {
	path := filepath.Join(testdataDir(t), testFile)

	// Ensure file exists from a prior download (or download it now).
	c := httpcache.New(testURL, path)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("initial Fetch: %v", err)
	}

	// Second fetch on the same Cacher should use ETag/Last-Modified.
	updated, err := c.Fetch()
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if updated {
		t.Error("second Fetch: expected updated=false (content unchanged)")
	}
	t.Log("conditional GET correctly returned 304 / not-modified")
}
