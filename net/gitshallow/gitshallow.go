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
	Branch string // Optional: specific branch to clone/pull

	mu sync.Mutex
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
		Branch: strings.TrimSpace(branch),
	}
}

// Clone performs a shallow clone (--depth N --single-branch --no-tags).
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

// runGit executes a git command in the repo directory (or parent for clone).
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

// Pull performs a shallow pull (--ff-only) and reports whether HEAD changed.
func (r *ShallowRepo) Pull() (updated bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.pull()
}

func (r *ShallowRepo) pull() (updated bool, err error) {
	if !r.exists() {
		return false, fmt.Errorf("repository does not exist at %s", r.Path)
	}

	oldHead, err := r.runGit("rev-parse", "HEAD")
	if err != nil {
		return false, err
	}

	pullArgs := []string{"pull", "--ff-only", "--no-tags"}
	if r.Depth == 0 {
		r.Depth = 1
	}
	if r.Depth >= 0 {
		pullArgs = append(pullArgs, "--depth", fmt.Sprintf("%d", r.Depth))
	}
	if r.Branch != "" {
		pullArgs = append(pullArgs, "origin", r.Branch)
	}
	if _, err = r.runGit(pullArgs...); err != nil {
		return false, err
	}

	newHead, err := r.runGit("rev-parse", "HEAD")
	if err != nil {
		return false, err
	}

	return oldHead != newHead, nil
}

// GC runs git gc. aggressiveGC adds --aggressive; pruneNow adds --prune=now.
func (r *ShallowRepo) GC(aggressiveGC, pruneNow bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.gc(aggressiveGC, pruneNow)
}

func (r *ShallowRepo) gc(aggressiveGC, pruneNow bool) error {
	if !r.exists() {
		return fmt.Errorf("repository does not exist at %s", r.Path)
	}

	args := []string{"gc"}
	if aggressiveGC {
		args = append(args, "--aggressive")
	}
	if pruneNow {
		args = append(args, "--prune=now")
	}

	_, err := r.runGit(args...)
	return err
}

// Sync clones if missing, pulls, and runs GC.
// lightGC=false (zero value) runs --aggressive GC with --prune=now to minimize disk use.
// Pass true to skip both when speed matters more than footprint.
func (r *ShallowRepo) Sync(lightGC bool) (updated bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cloned, err := r.clone(); err != nil {
		return false, err
	} else if cloned {
		return true, nil
	}

	updated, err = r.pull()
	if err != nil {
		return false, err
	}
	if !updated {
		return false, nil
	}

	if err := r.gc(!lightGC, !lightGC); err != nil {
		return true, fmt.Errorf("gc failed but pull succeeded: %w", err)
	}

	return true, nil
}
