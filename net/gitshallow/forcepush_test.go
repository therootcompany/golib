package gitshallow_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/therootcompany/golib/net/gitshallow"
)

// TestRepo_ForcePushRecovery verifies that Fetch transparently picks up an
// upstream history rewrite. The previous pull-based flow could fail with
// "refusing to merge unrelated histories"; the current fetch+reset must
// succeed and install the new HEAD.
func TestRepo_ForcePushRecovery(t *testing.T) {
	if _, err := exec.LookPath("git"); err != nil {
		t.Skip("git not available")
	}

	root := t.TempDir()
	upstream := filepath.Join(root, "upstream.git") // bare
	scratch := filepath.Join(root, "scratch")       // working copy that rewrites history
	clone := filepath.Join(root, "clone")           // gitshallow clone under test

	mustGit := func(t *testing.T, dir string, args ...string) {
		t.Helper()
		cmd := exec.Command("git", args...)
		cmd.Dir = dir
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=test", "GIT_AUTHOR_EMAIL=test@example.com",
			"GIT_COMMITTER_NAME=test", "GIT_COMMITTER_EMAIL=test@example.com",
		)
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("git %v (in %s): %v\n%s", args, dir, err, out)
		}
	}

	// Bare upstream.
	if err := os.MkdirAll(upstream, 0o755); err != nil {
		t.Fatal(err)
	}
	mustGit(t, upstream, "init", "--bare", "--initial-branch=main")

	// Scratch working copy with one commit, push to upstream.
	if err := os.MkdirAll(scratch, 0o755); err != nil {
		t.Fatal(err)
	}
	mustGit(t, scratch, "init", "--initial-branch=main")
	mustGit(t, scratch, "remote", "add", "origin", upstream)
	if err := os.WriteFile(filepath.Join(scratch, "data.txt"), []byte("v1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, scratch, "add", "data.txt")
	mustGit(t, scratch, "commit", "-m", "v1")
	mustGit(t, scratch, "push", "-u", "origin", "main")

	// gitshallow clones, reads v1.
	repo := gitshallow.New(upstream, clone, 1, "main")
	if updated, err := repo.Fetch(t.Context()); err != nil {
		t.Fatalf("first Fetch: %v", err)
	} else if !updated {
		t.Fatal("first Fetch: expected updated=true")
	}
	got, err := os.ReadFile(filepath.Join(clone, "data.txt"))
	if err != nil {
		t.Fatalf("read v1: %v", err)
	}
	if string(got) != "v1\n" {
		t.Fatalf("v1: got %q want %q", got, "v1\n")
	}

	// Rewrite upstream history with an unrelated commit and force-push.
	mustGit(t, scratch, "checkout", "--orphan", "fresh")
	mustGit(t, scratch, "rm", "-rf", ".")
	if err := os.WriteFile(filepath.Join(scratch, "data.txt"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	mustGit(t, scratch, "add", "data.txt")
	mustGit(t, scratch, "commit", "-m", "v2")
	mustGit(t, scratch, "branch", "-M", "main")
	mustGit(t, scratch, "push", "--force", "origin", "main")

	// gitshallow must recover — fetch+reset, not pull --ff-only.
	// Use a fresh instance: the same *Repo has a 1s debounce that would
	// skip the follow-up fetch in this test's wall-clock window.
	repo2 := gitshallow.New(upstream, clone, 1, "main")
	updated, err := repo2.Fetch(t.Context())
	if err != nil {
		t.Fatalf("post-force-push Fetch: %v", err)
	}
	if !updated {
		t.Error("post-force-push Fetch: expected updated=true")
	}
	got, err = os.ReadFile(filepath.Join(clone, "data.txt"))
	if err != nil {
		t.Fatalf("read v2: %v", err)
	}
	if string(got) != "v2\n" {
		t.Fatalf("v2: got %q want %q", got, "v2\n")
	}
}
