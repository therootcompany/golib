package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/therootcompany/golib/fs/dataset"
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

	var blacklist *dataset.File[ipcohort.Cohort]

	if gitURL != "" {
		repoDir := filepath.Dir(dataPath)
		relPath := filepath.Base(dataPath)
		repo := dataset.NewRepo(gitURL, repoDir)
		blacklist = dataset.AddFile(repo, relPath, ipcohort.LoadFile)
		fmt.Fprintf(os.Stderr, "Syncing %q ...\n", repoDir)
		if err := repo.Init(); err != nil {
			fmt.Fprintf(os.Stderr, "error: git sync: %v\n", err)
			os.Exit(1)
		}
	} else {
		blacklist = dataset.NewFile(dataPath, ipcohort.LoadFile)
		fmt.Fprintf(os.Stderr, "Loading %q ...\n", dataPath)
		if err := blacklist.Reload(); err != nil {
			fmt.Fprintf(os.Stderr, "error: load: %v\n", err)
			os.Exit(1)
		}
	}

	c := blacklist.Load()
	fmt.Fprintf(os.Stderr, "Loaded %d entries\n", c.Size())

	if c.Contains(ipStr) {
		fmt.Printf("%s is BLOCKED\n", ipStr)
		os.Exit(1)
	}

	fmt.Printf("%s is allowed\n", ipStr)
}
