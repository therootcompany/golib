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

// outbound blocklist
const (
	outboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/single_ips.txt"
	outboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/networks.txt"
)

func main() {
	if len(os.Args) < 3 {
		fmt.Fprintf(os.Stderr, "Usage: %s <cache-dir|blacklist.txt> <ip-address> [git-url]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  No remote:  load from <blacklist.txt> (inbound only)\n")
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

	var f *IPFilter
	switch {
	case gitURL != "":
		f = NewGitFilter(gitURL, dataPath,
			nil,
			[]string{"tables/inbound/single_ips.txt", "tables/inbound/networks.txt"},
			[]string{"tables/outbound/single_ips.txt", "tables/outbound/networks.txt"},
		)
	case strings.HasSuffix(dataPath, ".txt") || strings.HasSuffix(dataPath, ".csv"):
		f = NewFileFilter(nil, []string{dataPath}, nil)
	default:
		// dataPath is a cache directory; fetch the pre-split files via HTTP
		f = NewHTTPFilter(
			nil,
			[]HTTPSource{
				{inboundSingleURL, dataPath + "/inbound_single_ips.txt"},
				{inboundNetworkURL, dataPath + "/inbound_networks.txt"},
			},
			[]HTTPSource{
				{outboundSingleURL, dataPath + "/outbound_single_ips.txt"},
				{outboundNetworkURL, dataPath + "/outbound_networks.txt"},
			},
		)
	}

	if err := f.Init(false); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n", f.InboundSize(), f.OutboundSize())

	blockedInbound := f.ContainsInbound(ipStr)
	blockedOutbound := f.ContainsOutbound(ipStr)

	switch {
	case blockedInbound && blockedOutbound:
		fmt.Printf("%s is BLOCKED (inbound + outbound)\n", ipStr)
		os.Exit(1)
	case blockedInbound:
		fmt.Printf("%s is BLOCKED (inbound)\n", ipStr)
		os.Exit(1)
	case blockedOutbound:
		fmt.Printf("%s is BLOCKED (outbound)\n", ipStr)
		os.Exit(1)
	default:
		fmt.Printf("%s is allowed\n", ipStr)
	}
}
