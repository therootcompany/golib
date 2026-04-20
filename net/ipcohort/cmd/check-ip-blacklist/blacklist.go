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

// HTTPSource pairs a remote URL with a local cache path.
type HTTPSource struct {
	URL  string
	Path string
}

type Blacklist struct {
	atomic.Pointer[ipcohort.Cohort]
	paths []string
	git   *gitshallow.Repo
	http  []*httpcache.Cacher
}

// NewBlacklist loads from one or more local files.
func NewBlacklist(paths ...string) *Blacklist {
	return &Blacklist{paths: paths}
}

// NewGitBlacklist clones/pulls gitURL into repoDir and loads relPaths on each update.
func NewGitBlacklist(gitURL, repoDir string, relPaths ...string) *Blacklist {
	repo := gitshallow.New(gitURL, repoDir, 1, "")
	paths := make([]string, len(relPaths))
	for i, p := range relPaths {
		paths[i] = filepath.Join(repoDir, p)
	}
	b := &Blacklist{paths: paths, git: repo}
	repo.Register(b.reload)
	return b
}

// NewHTTPBlacklist fetches each source URL to its local path, reloading on any change.
func NewHTTPBlacklist(sources ...HTTPSource) *Blacklist {
	b := &Blacklist{}
	for _, src := range sources {
		b.paths = append(b.paths, src.Path)
		c := httpcache.New(src.URL, src.Path)
		c.Register(b.reload)
		b.http = append(b.http, c)
	}
	return b
}

func (b *Blacklist) Init(lightGC bool) error {
	switch {
	case b.git != nil:
		return b.git.Init(lightGC)
	case len(b.http) > 0:
		for _, c := range b.http {
			if err := c.Init(); err != nil {
				return err
			}
		}
		return nil
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
	case len(b.http) > 0:
		var anyUpdated bool
		for _, c := range b.http {
			updated, err := c.Sync()
			if err != nil {
				return anyUpdated, err
			}
			anyUpdated = anyUpdated || updated
		}
		return anyUpdated, nil
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
	c, err := ipcohort.LoadFiles(b.paths...)
	if err != nil {
		return err
	}
	b.Store(c)
	return nil
}
