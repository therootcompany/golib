package gitshallow

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
)

// Repo manages a shallow git clone used as a periodically-updated data source.
type Repo struct {
	URL    string
	Path   string
	Depth  int    // 0 defaults to 1, -1 for all
	Branch string // Optional: specific branch to clone/pull

	// GCInterval controls explicit aggressive GC after pulls.
	//   0 (default) — no explicit gc; git runs gc.auto on its own schedule
	//   1           — aggressive gc after every pull
	//   N           — aggressive gc after every Nth pull
	GCInterval int

	mu        sync.Mutex
	pullCount int
}

// New creates a new Repo instance.
func New(url, path string, depth int, branch string) *Repo {
	return &Repo{
		URL:    url,
		Path:   path,
		Depth:  depth,
		Branch: strings.TrimSpace(branch),
	}
}

// effectiveDepth returns the depth to use for clone/pull.
// 0 means unset — defaults to 1. -1 means full history.
func (r *Repo) effectiveDepth() int {
	if r.Depth == 0 {
		return 1
	}
	return r.Depth
}

// Init clones the repo if missing, then syncs once.
// Returns whether anything new was fetched.
func (r *Repo) Init() (bool, error) {
	gitDir := filepath.Join(r.Path, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if _, err := r.Clone(); err != nil {
			return false, err
		}
	}
	return r.syncGit()
}

// Clone performs a shallow clone (--depth N --single-branch --no-tags).
func (r *Repo) Clone() (bool, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.clone()
}

func (r *Repo) clone() (bool, error) {
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
	if depth := r.effectiveDepth(); depth >= 0 {
		args = append(args, "--depth", fmt.Sprintf("%d", depth))
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
func (r *Repo) exists() bool {
	_, err := os.Stat(filepath.Join(r.Path, ".git"))
	return err == nil
}

// runGit executes a git command in the repo directory (or parent for clone).
func (r *Repo) runGit(args ...string) (string, error) {
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
func (r *Repo) Pull() (updated bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.pull()
}

func (r *Repo) pull() (updated bool, err error) {
	if !r.exists() {
		return false, fmt.Errorf("repository does not exist at %s", r.Path)
	}

	oldHead, err := r.runGit("rev-parse", "HEAD")
	if err != nil {
		return false, err
	}

	pullArgs := []string{"pull", "--ff-only", "--no-tags"}
	if depth := r.effectiveDepth(); depth >= 0 {
		pullArgs = append(pullArgs, "--depth", fmt.Sprintf("%d", depth))
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

// GC runs git gc --aggressive --prune=now.
func (r *Repo) GC() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.gc()
}

func (r *Repo) gc() error {
	if !r.exists() {
		return fmt.Errorf("repository does not exist at %s", r.Path)
	}
	_, err := r.runGit("gc", "--aggressive", "--prune=now")
	return err
}

// Sync clones if missing, pulls, and conditionally runs GC based on GCEvery.
// Returns whether HEAD changed.
func (r *Repo) Sync() (bool, error) {
	return r.syncGit()
}

// Fetch satisfies httpcache.Syncer.
func (r *Repo) Fetch() (bool, error) {
	return r.syncGit()
}

func (r *Repo) syncGit() (updated bool, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()

	if cloned, err := r.clone(); err != nil {
		return false, err
	} else if cloned {
		return true, nil
	}

	updated, err = r.pull()
	if err != nil || !updated {
		return updated, err
	}

	if r.GCInterval > 0 {
		r.pullCount++
		if r.pullCount%r.GCInterval == 0 {
			return true, r.gc()
		}
	}

	return true, nil
}
