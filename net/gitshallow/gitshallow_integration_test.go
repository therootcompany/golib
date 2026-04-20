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

func TestRepo_Clone(t *testing.T) {
	repoDir := filepath.Join(testdataDir(t), "gitshallow_ipblocklist")
	os.RemoveAll(repoDir) // start fresh

	repo := gitshallow.New(testRepoURL, repoDir, 1, "")

	updated, err := repo.Fetch()
	if err != nil {
		t.Fatalf("Fetch (clone): %v", err)
	}
	if !updated {
		t.Error("first Fetch: expected updated=true after fresh clone")
	}

	// Verify expected files are present.
	for _, rel := range []string{
		"tables/inbound/single_ips.txt",
		"tables/inbound/networks.txt",
		"tables/outbound/single_ips.txt",
		"tables/outbound/networks.txt",
	} {
		p := filepath.Join(repoDir, rel)
		if info, err := os.Stat(p); err != nil {
			t.Errorf("expected file missing: %s", rel)
		} else {
			t.Logf("%s: %d bytes", rel, info.Size())
		}
	}
}

func TestRepo_Pull(t *testing.T) {
	repoDir := filepath.Join(testdataDir(t), "gitshallow_ipblocklist")

	repo := gitshallow.New(testRepoURL, repoDir, 1, "")

	// Ensure cloned first.
	if _, err := repo.Fetch(); err != nil {
		t.Fatalf("initial Fetch: %v", err)
	}

	// Pull again — already up to date, updated may be true or false.
	_, err := repo.Fetch()
	if err != nil {
		t.Fatalf("second Fetch (pull): %v", err)
	}
	t.Log("pull completed without error")
}
