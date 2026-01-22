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

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <blacklist.csv> <ip-address>\n", os.Args[0])
		os.Exit(1)
	}

	path := os.Args[1]
	ipStr := os.Args[2]

	fmt.Fprintf(os.Stderr, "Loading %q ...\n", path)

	gitURL := ""
	r := NewReloader(gitURL, path)
	fmt.Fprintf(os.Stderr, "Syncing git repo ...\n")
	if n, err := r.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "error: ip cohort: %v\n", err)
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "ip cohort: loaded %d blacklist entries\n", n)
	}

	fmt.Fprintf(os.Stderr, "Checking blacklist ...\n")
	if r.Blacklist.Contains(ipStr) {
		fmt.Printf("%s is BLOCKED\n", ipStr)
		os.Exit(1)
	}

	fmt.Printf("%s is allowed\n", ipStr)
}

type Reloader struct {
	Blacklist   *ipcohort.Cohort
	gitRepo     string
	shallowRepo *gitshallow.ShallowRepo
	path        string
}

func NewReloader(gitURL, path string) *Reloader {
	gitRepo := filepath.Dir(path)
	gitDepth := 1
	gitBranch := ""
	shallowRepo := gitshallow.New(gitURL, gitRepo, gitDepth, gitBranch)

	return &Reloader{
		Blacklist:   nil,
		gitRepo:     gitRepo,
		shallowRepo: shallowRepo,
		path:        path,
	}
}

func (r *Reloader) Init() (int, error) {
	blacklist, err := ipcohort.LoadFile(r.path, false)
	if err != nil {
		return 0, err
	}
	r.Blacklist = blacklist

	gitDir := filepath.Join(r.gitRepo, ".git")
	if _, err := os.Stat(gitDir); err != nil {
		log.Fatalf("Failed to load blacklist: %v", err)
		fmt.Printf("%q is not a git repo, skipping sync\n", r.gitRepo)
		return blacklist.Size(), nil
	}

	return r.reload()
}

func (r Reloader) Run(ctx context.Context) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if n, err := r.reload(); err != nil {
				fmt.Fprintf(os.Stderr, "error: ip cohort: %v\n", err)
			} else {
				fmt.Fprintf(os.Stderr, "ip cohort: loaded %d blacklist entries\n", n)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (r Reloader) reload() (int, error) {
	laxGC := false
	lazyPrune := false
	updated, err := r.shallowRepo.Sync(laxGC, lazyPrune)
	if err != nil {
		return 0, fmt.Errorf("git sync: %w", err)
	}
	if !updated {
		return 0, nil
	}

	needsSort := false
	nextCohort, err := ipcohort.LoadFile(r.path, needsSort)
	if err != nil {
		return 0, fmt.Errorf("ip cohort: %w", err)
	}

	r.Blacklist.Swap(nextCohort)
	return r.Blacklist.Size(), nil
}
