//go:build integration

package gitshallow_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/therootcompany/golib/net/gitshallow"
)

const testRepoURL = "https://github.com/bitwire-it/ipblocklist"

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

func repoDir(t *testing.T) string {
	return filepath.Join(testdataDir(t), "gitshallow_ipblocklist")
}

func TestRepo_Clone(t *testing.T) {
	dir := repoDir(t)
	os.RemoveAll(dir)

	repo := gitshallow.New(testRepoURL, dir, 1, "")
	updated, err := repo.Fetch()
	if err != nil {
		t.Fatalf("Fetch (clone): %v", err)
	}
	if !updated {
		t.Error("fresh clone: expected updated=true")
	}

	for _, rel := range []string{
		"tables/inbound/single_ips.txt",
		"tables/inbound/networks.txt",
		"tables/outbound/single_ips.txt",
		"tables/outbound/networks.txt",
	} {
		info, err := os.Stat(filepath.Join(dir, rel))
		if err != nil {
			t.Errorf("expected file missing: %s", rel)
		} else {
			t.Logf("%s: %d bytes", rel, info.Size())
		}
	}
}

func TestRepo_Pull_SameInstance(t *testing.T) {
	dir := repoDir(t)

	repo := gitshallow.New(testRepoURL, dir, 1, "")
	// Ensure cloned.
	if _, err := repo.Fetch(); err != nil {
		t.Fatalf("initial Fetch: %v", err)
	}

	// Second pull on the same instance — already at HEAD, should not advance.
	updated, err := repo.Fetch()
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}
	if updated {
		t.Error("same-instance second pull: expected updated=false (already at HEAD)")
	}
	t.Log("same-instance pull correctly reported no update")
}

func TestRepo_Pull_FreshInstance(t *testing.T) {
	dir := repoDir(t)

	// Ensure cloned via a first instance.
	first := gitshallow.New(testRepoURL, dir, 1, "")
	if _, err := first.Fetch(); err != nil {
		t.Fatalf("initial Fetch: %v", err)
	}

	// Fresh instance with no in-memory state — git HEAD on disk drives the check.
	fresh := gitshallow.New(testRepoURL, dir, 1, "")
	updated, err := fresh.Fetch()
	if err != nil {
		t.Fatalf("fresh-instance Fetch: %v", err)
	}
	if updated {
		t.Error("fresh-instance pull: expected updated=false (HEAD unchanged on disk)")
	}
	t.Log("fresh-instance pull correctly reported no update")
}
