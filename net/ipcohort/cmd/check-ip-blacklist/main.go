package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sync/atomic"

	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/ipcohort"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <blacklist.csv> <ip-address> [git-url]\n", os.Args[0])
		os.Exit(1)
	}

	dataPath := os.Args[1]
	ipStr := os.Args[2]
	gitURL := ""
	if len(os.Args) >= 4 {
		gitURL = os.Args[3]
	}

	var cohort atomic.Pointer[ipcohort.Cohort]

	load := func() error {
		c, err := ipcohort.LoadFile(dataPath)
		if err != nil {
			return err
		}
		cohort.Store(c)
		return nil
	}

	if gitURL != "" {
		repoDir := filepath.Dir(dataPath)
		repo := gitshallow.New(gitURL, repoDir, 1, "")
		repo.Register(load)
		fmt.Fprintf(os.Stderr, "Syncing %q ...\n", repoDir)
		if err := repo.Init(false); err != nil {
			fmt.Fprintf(os.Stderr, "error: git sync: %v\n", err)
			os.Exit(1)
		}
	} else {
		fmt.Fprintf(os.Stderr, "Loading %q ...\n", dataPath)
		if err := load(); err != nil {
			fmt.Fprintf(os.Stderr, "error: load: %v\n", err)
			os.Exit(1)
		}
	}

	c := cohort.Load()
	fmt.Fprintf(os.Stderr, "Loaded %d entries\n", c.Size())

	if c.Contains(ipStr) {
		fmt.Printf("%s is BLOCKED\n", ipStr)
		os.Exit(1)
	}

	fmt.Printf("%s is allowed\n", ipStr)
}
