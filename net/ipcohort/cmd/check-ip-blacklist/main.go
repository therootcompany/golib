package main

import (
	"fmt"
	"os"

	"github.com/therootcompany/golib/net/gitdataset"
	"github.com/therootcompany/golib/net/ipcohort"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <blacklist.csv> <ip-address>\n", os.Args[0])
		os.Exit(1)
	}

	dataPath := os.Args[1]
	ipStr := os.Args[2]
	gitURL := ""
	if len(os.Args) >= 4 {
		gitURL = os.Args[3]
	}

	fmt.Fprintf(os.Stderr, "Loading %q ...\n", dataPath)

	var b *ipcohort.Cohort
	loadFile := func(path string) (*ipcohort.Cohort, error) {
		return ipcohort.LoadFile(path, false)
	}
	blacklist := gitdataset.New(gitURL, dataPath, loadFile)
	fmt.Fprintf(os.Stderr, "Syncing git repo ...\n")
	if updated, err := blacklist.Init(false); err != nil {
		fmt.Fprintf(os.Stderr, "error: ip cohort: %v\n", err)
	} else {
		b = blacklist.Load()
		if updated {
			n := b.Size()
			if n > 0 {
				fmt.Fprintf(os.Stderr, "ip cohort: loaded %d blacklist entries\n", n)
			}
		}
	}

	fmt.Fprintf(os.Stderr, "Checking blacklist ...\n")
	if blacklist.Load().Contains(ipStr) {
		fmt.Printf("%s is BLOCKED\n", ipStr)
		os.Exit(1)
	}

	fmt.Printf("%s is allowed\n", ipStr)
}
