package dataset

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
)

// File holds an atomically-swappable pointer to a value loaded from a file.
// Reads are lock-free. Use NewFile for file-only use, or AddFile to attach
// to a GitRepo so the value refreshes whenever the repo is updated.
type File[T any] struct {
	atomic.Pointer[T]
	path     string
	loadFile func(string) (*T, error)
}

// NewFile creates a file-backed dataset with no git dependency.
// Call Reload to do the initial load and after any file change.
func NewFile[T any](path string, loadFile func(string) (*T, error)) *File[T] {
	d := &File[T]{
		path:     path,
		loadFile: loadFile,
	}
	d.Store(new(T))
	return d
}

// Reload reads the file and atomically replaces the stored value.
func (d *File[T]) Reload() error {
	v, err := d.loadFile(d.path)
	if err != nil {
		return err
	}
	d.Store(v)
	return nil
}

func (d *File[T]) reloadFile() error {
	return d.Reload()
}

// reloader is the internal interface GitRepo uses to trigger file reloads.
type reloader interface {
	reloadFile() error
}

// GitRepo manages a shallow git clone and reloads all registered files
// whenever the repo is updated. Multiple files from the same repo share
// one clone and one pull, avoiding git file-lock conflicts.
type GitRepo struct {
	path        string
	shallowRepo *gitshallow.ShallowRepo
	files       []reloader
}

// NewRepo creates a GitRepo backed by the given git URL, cloning into repoPath.
func NewRepo(gitURL, repoPath string) *GitRepo {
	return &GitRepo{
		path:        repoPath,
		shallowRepo: gitshallow.New(gitURL, repoPath, 1, ""),
	}
}

// AddFile registers a file inside this repo and returns its handle.
// relPath is relative to the repo root. The file is reloaded automatically
// whenever the repo is synced via Init or Run.
func AddFile[T any](repo *GitRepo, relPath string, loadFile func(string) (*T, error)) *File[T] {
	d := NewFile(filepath.Join(repo.path, relPath), loadFile)
	repo.files = append(repo.files, d)
	return d
}

// Init clones the repo if missing, syncs once, and loads all registered files.
// Always runs aggressive GC — acceptable as a one-time startup cost.
func (r *GitRepo) Init() error {
	gitDir := filepath.Join(r.path, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if _, err := r.shallowRepo.Clone(); err != nil {
			return err
		}
	}
	_, err := r.sync(false, true)
	return err
}

// Run periodically syncs the repo and reloads files. Blocks until ctx is done.
// lightGC=false (zero value) runs aggressive GC with immediate pruning to keep footprint minimal.
// Pass true to skip both when the periodic GC is too slow for your workload.
func (r *GitRepo) Run(ctx context.Context, lightGC bool) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if updated, err := r.sync(lightGC, false); err != nil {
				fmt.Fprintf(os.Stderr, "error: git repo sync: %v\n", err)
			} else if updated {
				fmt.Fprintf(os.Stderr, "git repo: files reloaded\n")
			}
		case <-ctx.Done():
			return
		}
	}
}

// Sync pulls the latest commits and reloads all files if HEAD changed.
// lightGC=false (zero value) runs aggressive GC with immediate pruning to keep footprint minimal.
func (r *GitRepo) Sync(lightGC bool) (bool, error) {
	return r.sync(lightGC, false)
}

func (r *GitRepo) sync(lightGC, force bool) (bool, error) {
	updated, err := r.shallowRepo.Sync(lightGC)
	if err != nil {
		return false, fmt.Errorf("git sync: %w", err)
	}
	if !updated && !force {
		return false, nil
	}

	for _, f := range r.files {
		if err := f.reloadFile(); err != nil {
			fmt.Fprintf(os.Stderr, "error: reload file: %v\n", err)
		}
	}
	return true, nil
}
