package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <blacklist.csv> <ip-address>\n", os.Args[0])
		os.Exit(1)
	}

	path := os.Args[1]
	ipStr := os.Args[2]
	gitURL := ""
	if len(os.Args) >= 4 {
		gitURL = os.Args[3]
	}

	fmt.Fprintf(os.Stderr, "Loading %q ...\n", path)

	b := NewBlacklist(gitURL, path)
	fmt.Fprintf(os.Stderr, "Syncing git repo ...\n")
	if n, err := b.Init(false); err != nil {
		fmt.Fprintf(os.Stderr, "error: ip cohort: %v\n", err)
	} else if n > 0 {
		fmt.Fprintf(os.Stderr, "ip cohort: loaded %d blacklist entries\n", n)
	}

	fmt.Fprintf(os.Stderr, "Checking blacklist ...\n")
	if b.Contains(ipStr) {
		fmt.Printf("%s is BLOCKED\n", ipStr)
		os.Exit(1)
	}

	fmt.Printf("%s is allowed\n", ipStr)
}
