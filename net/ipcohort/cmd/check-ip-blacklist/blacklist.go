package main

import (
	"context"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/ipcohort"
)

type Blacklist struct {
	*ipcohort.Cohort
	gitRepo     string
	shallowRepo *gitshallow.ShallowRepo
	path        string
}

func NewBlacklist(gitURL, path string) *Blacklist {
	gitRepo := filepath.Dir(path)
	gitDepth := 1
	gitBranch := ""
	shallowRepo := gitshallow.New(gitURL, gitRepo, gitDepth, gitBranch)

	return &Blacklist{
		Cohort:      ipcohort.New(),
		gitRepo:     gitRepo,
		shallowRepo: shallowRepo,
		path:        path,
	}
}

func (b *Blacklist) Init(skipGC bool) (int, error) {
	gitDir := filepath.Join(b.gitRepo, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		if _, err := b.shallowRepo.Clone(); err != nil {
			log.Fatalf("Failed to load blacklist: %v", err)
			fmt.Printf("%q is not a git repo, skipping sync\n", b.gitRepo)
			return b.Size(), nil
		}
	}

	force := true
	return b.reload(skipGC, force)
}

func (r Blacklist) Run(ctx context.Context) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if n, err := r.reload(false, false); err != nil {
				fmt.Fprintf(os.Stderr, "error: ip cohort: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "ip cohort: loaded %d blacklist entries\n", n)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (b Blacklist) reload(skipGC, force bool) (int, error) {
	laxGC := skipGC
	lazyPrune := skipGC
	updated, err := b.shallowRepo.Sync(laxGC, lazyPrune)
	if err != nil {
		return 0, fmt.Errorf("git sync: %w", err)
	}
	if !updated && !force {
		return 0, nil
	}

	needsSort := false
	nextCohort, err := ipcohort.LoadFile(b.path, needsSort)
	if err != nil {
		return 0, fmt.Errorf("ip cohort: %w", err)
	}

	b.Swap(nextCohort)
	return b.Size(), nil
}
