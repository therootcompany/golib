package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/ipcohort"
)

type Blacklist struct {
	atomic.Pointer[ipcohort.Cohort]
	path string
	repo *gitshallow.Repo // nil if file-only
}

func NewBlacklist(path string) *Blacklist {
	return &Blacklist{path: path}
}

func NewGitBlacklist(gitURL, path string) *Blacklist {
	repo := gitshallow.New(gitURL, filepath.Dir(path), 1, "")
	b := &Blacklist{path: path, repo: repo}
	repo.Register(b.reload)
	return b
}

func (b *Blacklist) Init(lightGC bool) error {
	if b.repo != nil {
		return b.repo.Init(lightGC)
	}
	return b.reload()
}

func (b *Blacklist) Run(ctx context.Context, lightGC bool) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if updated, err := b.repo.Sync(lightGC); err != nil {
				fmt.Fprintf(os.Stderr, "error: blacklist sync: %v\n", err)
			} else if updated {
				fmt.Fprintf(os.Stderr, "blacklist: reloaded %d entries\n", b.Size())
			}
		case <-ctx.Done():
			return
		}
	}
}

func (b *Blacklist) Contains(ipStr string) bool {
	return b.Load().Contains(ipStr)
}

func (b *Blacklist) Size() int {
	return b.Load().Size()
}

func (b *Blacklist) reload() error {
	c, err := ipcohort.LoadFile(b.path)
	if err != nil {
		return err
	}
	b.Store(c)
	return nil
}
