package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
)

type Blacklist struct {
	atomic.Pointer[ipcohort.Cohort]
	path string
	git  *gitshallow.Repo
	http *httpcache.Cacher
}

func NewBlacklist(path string) *Blacklist {
	return &Blacklist{path: path}
}

func NewGitBlacklist(gitURL, path string) *Blacklist {
	repo := gitshallow.New(gitURL, filepath.Dir(path), 1, "")
	b := &Blacklist{path: path, git: repo}
	repo.Register(b.reload)
	return b
}

func NewHTTPBlacklist(url, path string) *Blacklist {
	cacher := httpcache.New(url, path)
	b := &Blacklist{path: path, http: cacher}
	cacher.Register(b.reload)
	return b
}

func (b *Blacklist) Init(lightGC bool) error {
	switch {
	case b.git != nil:
		return b.git.Init(lightGC)
	case b.http != nil:
		return b.http.Init()
	default:
		return b.reload()
	}
}

func (b *Blacklist) Run(ctx context.Context, lightGC bool) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updated, err := b.sync(lightGC)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: blacklist sync: %v\n", err)
			} else if updated {
				fmt.Fprintf(os.Stderr, "blacklist: reloaded %d entries\n", b.Size())
			}
		case <-ctx.Done():
			return
		}
	}
}

func (b *Blacklist) sync(lightGC bool) (bool, error) {
	switch {
	case b.git != nil:
		return b.git.Sync(lightGC)
	case b.http != nil:
		return b.http.Sync()
	default:
		return false, nil
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
