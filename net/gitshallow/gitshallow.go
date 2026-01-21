package gitshallow

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// ShallowRepo represents a shallow Git repository manager.
type ShallowRepo struct {
	URL    string
	Path   string
	Depth  int    // 0 defaults to 1, -1 for all
	Branch string // Optional: specific branch to clone/fetch
	//WithBranches bool
	//WithTags bool

	mu sync.Mutex // Mutex for in-process locking
}

// New creates a new ShallowRepo instance.
func New(url, path string, depth int, branch string) *ShallowRepo {
	if depth == 0 {
		depth = 1
	}
	return &ShallowRepo{
		URL:    url,
		Path:   path,
		Depth:  depth,
		Branch: strings.TrimSpace(branch), // clean up accidental whitespace
	}
}

// Clone performs a shallow clone (default --depth 0 --single-branch, --no-tags, etc).
func (r *ShallowRepo) Clone() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.clone()
}

func (r *ShallowRepo) clone() (bool, error) {
	if r.exists() {
		return false, nil
	}

	if r.URL == "" {
		return false, fmt.Errorf("repository URL is required")
	}
	if r.Path == "" {
		return false, fmt.Errorf("local path is required")
	}

	args := []string{"clone", "--no-tags"}
	if r.Depth == 0 {
		r.Depth = 1
	}
	if r.Depth >= 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", r.Depth))
	}
	args = append(args, "--single-branch")
	if r.Branch != "" {
		args = append(args, "--branch", r.Branch)
	}
	args = append(args, r.URL, filepath.Base(r.Path))

	_, err := r.runGit(args...)
	return true, err
}

// exists checks if the directory contains a .git folder.
func (r *ShallowRepo) exists() bool {
	_, err := os.Stat(filepath.Join(r.Path, ".git"))
	return err == nil
}

// runGit executes a git command.
// For clone it runs in the parent directory; otherwise inside the repo.
func (r *ShallowRepo) runGit(args ...string) (string, error) {
	cmd := exec.Command("git", args...)

	if _, err := os.Stat(r.Path); err == nil && r.exists() {
		cmd.Dir = r.Path
	} else {
		cmd.Dir = filepath.Dir(r.Path)
	}

	output, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s failed: %v\n%s", strings.Join(args, " "), err, output)
	}

	return strings.TrimSpace(string(output)), nil
}

// Fetch performs a shallow fetch and updates the working branch.
// Returns true if HEAD changed (i.e. meaningful update occurred).
// Uses --depth on fetch; branch filtering only when Branch is set.
func (r *ShallowRepo) Fetch() (updated bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.fetch()
}

func (r *ShallowRepo) fetch() (updated bool, err error) {
	if !r.exists() {
		return false, fmt.Errorf("repository does not exist at %s", r.Path)
	}

	// Remember current HEAD
	oldHead, err := r.runGit("-C", r.Path, "rev-parse", "HEAD")
	if err != nil {
		return false, err
	}

	// Update local branch (git pull --ff-only is safer in shallow context)
	pullArgs := []string{"-C", r.Path, "pull", "--ff-only"}
	if r.Branch != "" {
		pullArgs = append(pullArgs, "origin", r.Branch)
	}
	_, err = r.runGit(pullArgs...)
	if err != nil {
		return false, err
	}

	// Fetch
	fetchArgs := []string{"-C", r.Path, "fetch", "--no-tags"}
	if r.Depth == 0 {
		r.Depth = 1
	}
	if r.Depth >= 0 {
		fetchArgs = append(fetchArgs, "--depth", fmt.Sprintf("%d", r.Depth))
	}
	_, err = r.runGit(fetchArgs...)
	if err != nil {
		return false, err
	}

	newHead, err := r.runGit("-C", r.Path, "rev-parse", "HEAD")
	if err != nil {
		return false, err
	}

	return oldHead != newHead, nil
}

// GC runs git gc, defaulting to pruning immediately and aggressively
func (r *ShallowRepo) GC(lax, lazy bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.gc(lax, lazy)
}

func (r *ShallowRepo) gc(lax, lazy bool) error {
	if !r.exists() {
		return fmt.Errorf("repository does not exist at %s", r.Path)
	}

	args := []string{"-C", r.Path, "gc"}
	if !lax {
		args = append(args, "--aggressive")
	}
	if !lazy {
		args = append(args, "--prune=now")
	}

	_, err := r.runGit(args...)
	return err
}

// Sync clones if missing, fetches, and runs GC.
// Returns whether fetch caused an update.
func (r *ShallowRepo) Sync(laxGC, lazyPrune bool) (updated bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if updated, err := r.clone(); err != nil {
		return false, err
	} else if updated {
		return updated, nil
	}

	if updated, err := r.fetch(); err != nil {
		return updated, err
	} else if !updated {
		return false, nil
	}

	if err := r.gc(laxGC, lazyPrune); err != nil {
		return updated, fmt.Errorf("gc failed but fetch succeeded: %w", err)
	}

	return updated, nil
}
