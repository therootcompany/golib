package gitdataset

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
)

// TODO maybe a GitRepo should contain GitDatasets such that loading
// multiple datasets from the same GitRepo won't cause issues with file locking?

type GitDataset[T any] struct {
	LoadFile func(path string) (*T, error)
	atomic.Pointer[T]
	gitRepo     string
	shallowRepo *gitshallow.ShallowRepo
	path        string
}

func New[T any](gitURL, path string, loadFile func(path string) (*T, error)) *GitDataset[T] {
	gitRepo := filepath.Dir(path)
	gitDepth := 1
	gitBranch := ""
	shallowRepo := gitshallow.New(gitURL, gitRepo, gitDepth, gitBranch)

	b := &GitDataset[T]{
		Pointer:     atomic.Pointer[T]{},
		LoadFile:    loadFile,
		gitRepo:     gitRepo,
		shallowRepo: shallowRepo,
		path:        path,
	}
	b.Store(new(T))
	return b
}

func (b *GitDataset[T]) Init(skipGC bool) (updated bool, err error) {
	gitDir := filepath.Join(b.gitRepo, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if _, err := b.shallowRepo.Clone(); err != nil {
			return false, err
		}
	}

	force := true
	return b.reload(skipGC, force)
}

func (b *GitDataset[T]) Run(ctx context.Context) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if ok, err := b.reload(false, false); err != nil {
				fmt.Fprintf(os.Stderr, "error: git data: %v\n", err)
			} else if ok {
				fmt.Fprintf(os.Stderr, "git data: loaded repo\n")
			} else {
				fmt.Fprintf(os.Stderr, "git data: already up-to-date\n")
			}
		case <-ctx.Done():
			return
		}
	}
}

func (b *GitDataset[T]) reload(skipGC, force bool) (updated bool, err error) {
	laxGC := skipGC
	lazyPrune := skipGC
	updated, err = b.shallowRepo.Sync(laxGC, lazyPrune)
	if err != nil {
		return false, fmt.Errorf("git sync: %w", err)
	}
	if !updated && !force {
		return false, nil
	}

	nextDataset, err := b.LoadFile(b.path)
	if err != nil {
		return false, err
	}

	_ = b.Swap(nextDataset)
	return true, nil
}
