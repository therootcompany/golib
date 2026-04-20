package main

import (
	"fmt"
	"os"
	"strings"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <blacklist.csv> <ip-address> [git-url|http-url]\n", os.Args[0])
		os.Exit(1)
	}

	dataPath := os.Args[1]
	ipStr := os.Args[2]
	remoteURL := ""
	if len(os.Args) >= 4 {
		remoteURL = os.Args[3]
	}

	var bl *Blacklist
	switch {
	case strings.HasPrefix(remoteURL, "http://") || strings.HasPrefix(remoteURL, "https://"):
		bl = NewHTTPBlacklist(remoteURL, dataPath)
	case remoteURL != "":
		bl = NewGitBlacklist(remoteURL, dataPath)
	default:
		bl = NewBlacklist(dataPath)
	}

	if err := bl.Init(false); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Loaded %d entries\n", bl.Size())

	if bl.Contains(ipStr) {
		fmt.Printf("%s is BLOCKED\n", ipStr)
		os.Exit(1)
	}

	fmt.Printf("%s is allowed\n", ipStr)
}
