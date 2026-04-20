package gitshallow

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// Repo manages a shallow git clone used as a periodically-updated data source.
type Repo struct {
	URL    string
	Path   string
	Depth  int    // 0 defaults to 1, -1 for all
	Branch string // Optional: specific branch to clone/pull

	mu        sync.Mutex
	callbacks []func() error
}

// New creates a new Repo instance.
func New(url, path string, depth int, branch string) *Repo {
	if depth == 0 {
		depth = 1
	}
	return &Repo{
		URL:    url,
		Path:   path,
		Depth:  depth,
		Branch: strings.TrimSpace(branch),
	}
}

// Register adds a callback invoked after each successful clone or pull.
// Use this to reload files and update atomic pointers when the repo changes.
func (r *Repo) Register(fn func() error) {
	r.callbacks = append(r.callbacks, fn)
}

// Init clones the repo if missing, syncs once, then invokes all callbacks
// regardless of whether git had new commits — ensuring files are loaded on startup.
func (r *Repo) Init(lightGC bool) error {
	gitDir := filepath.Join(r.Path, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if _, err := r.Clone(); err != nil {
			return err
		}
	}

	if _, err := r.syncGit(lightGC); err != nil {
		return err
	}

	return r.invokeCallbacks()
}

// Run periodically syncs the repo and invokes callbacks when HEAD changes.
// Blocks until ctx is done.
// lightGC=false (zero value) runs aggressive GC with immediate pruning to minimize disk use.
// Pass true to skip both when the periodic GC is too slow for your workload.
func (r *Repo) Run(ctx context.Context, lightGC bool) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if updated, err := r.Sync(lightGC); err != nil {
				fmt.Fprintf(os.Stderr, "error: git sync: %v\n", err)
			} else if updated {
				fmt.Fprintf(os.Stderr, "git: repo updated\n")
			}
		case <-ctx.Done():
			return
		}
	}
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
func (r *Repo) GC(aggressiveGC, pruneNow bool) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	return r.gc(aggressiveGC, pruneNow)
}

func (r *Repo) gc(aggressiveGC, pruneNow bool) error {
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

// Sync clones if missing, pulls, runs GC, and invokes callbacks if HEAD changed.
// Returns whether HEAD changed.
// lightGC=false (zero value) runs aggressive GC with --prune=now to minimize disk use.
func (r *Repo) Sync(lightGC bool) (updated bool, err error) {
	updated, err = r.syncGit(lightGC)
	if err != nil || !updated {
		return updated, err
	}

	return true, r.invokeCallbacks()
}

func (r *Repo) syncGit(lightGC bool) (updated bool, err error) {
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

	return true, r.gc(!lightGC, !lightGC)
}

func (r *Repo) invokeCallbacks() error {
	for _, fn := range r.callbacks {
		if err := fn(); err != nil {
			fmt.Fprintf(os.Stderr, "error: reload callback: %v\n", err)
		}
	}
	return nil
}
