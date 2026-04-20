package main

import (
	"fmt"
	"os"
	"strings"
)

// inbound blocklist - pre-separated by type for independent ETag caching
const (
	inboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/single_ips.txt"
	inboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/networks.txt"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <cache-dir|blacklist.csv> <ip-address> [git-url]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  No remote:  load from <blacklist.csv>\n")
		fmt.Fprintf(os.Stderr, "  git URL:    clone/pull into <cache-dir>\n")
		fmt.Fprintf(os.Stderr, "  (default):  fetch via HTTP into <cache-dir>\n")
		os.Exit(1)
	}

	dataPath := os.Args[1]
	ipStr := os.Args[2]
	gitURL := ""
	if len(os.Args) >= 4 {
		gitURL = os.Args[3]
	}

	var bl *Blacklist
	switch {
	case gitURL != "":
		bl = NewGitBlacklist(gitURL, dataPath,
			"tables/inbound/single_ips.txt",
			"tables/inbound/networks.txt",
		)
	case strings.HasSuffix(dataPath, ".txt") || strings.HasSuffix(dataPath, ".csv"):
		bl = NewBlacklist(dataPath)
	default:
		// dataPath is a cache directory; fetch the pre-split files via HTTP
		bl = NewHTTPBlacklist(
			HTTPSource{inboundSingleURL, dataPath + "/single_ips.txt"},
			HTTPSource{inboundNetworkURL, dataPath + "/networks.txt"},
		)
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
