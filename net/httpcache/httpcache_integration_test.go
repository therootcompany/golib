//go:build integration

package httpcache_test

import (
	"encoding/json"
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
	os.Remove(path)
	os.Remove(path + ".meta")

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

func TestCacher_SidecarWritten(t *testing.T) {
	path := filepath.Join(testdataDir(t), testFile)
	os.Remove(path)
	os.Remove(path + ".meta")

	c := httpcache.New(testURL, path)
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
	if meta["etag"] == "" && meta["last_modified"] == "" {
		t.Error("sidecar has neither etag nor last_modified")
	}
	t.Logf("sidecar: %s", data)
}

func TestCacher_ConditionalGet_SameCacher(t *testing.T) {
	path := filepath.Join(testdataDir(t), testFile)

	c := httpcache.New(testURL, path)
	if _, err := c.Fetch(); err != nil {
		t.Fatalf("initial Fetch: %v", err)
	}

	// Second call on the same instance — ETag already in memory.
	updated, err := c.Fetch()
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if updated {
		t.Error("same-cacher second Fetch: expected updated=false")
	}
	t.Log("same-cacher conditional GET correctly skipped re-download")
}

func TestCacher_ConditionalGet_FreshCacher(t *testing.T) {
	path := filepath.Join(testdataDir(t), testFile)

	// Ensure file + sidecar exist.
	first := httpcache.New(testURL, path)
	if _, err := first.Fetch(); err != nil {
		t.Fatalf("initial Fetch: %v", err)
	}
	if _, err := os.Stat(path + ".meta"); err != nil {
		t.Fatalf("sidecar missing after first fetch: %v", err)
	}

	// New Cacher with no in-memory state — must read sidecar and send conditional GET.
	fresh := httpcache.New(testURL, path)
	updated, err := fresh.Fetch()
	if err != nil {
		t.Fatalf("fresh-cacher Fetch: %v", err)
	}
	if updated {
		t.Error("fresh-cacher Fetch: expected updated=false (sidecar should have provided ETag)")
	}
	t.Log("fresh-cacher conditional GET correctly used sidecar ETag")
}
