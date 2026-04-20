package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/ipcohort"
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

	var src *Sources
	switch {
	case gitURL != "":
		src = newGitSources(gitURL, dataPath,
			nil,
			[]string{"tables/inbound/single_ips.txt", "tables/inbound/networks.txt"},
			[]string{"tables/outbound/single_ips.txt", "tables/outbound/networks.txt"},
		)
	case strings.HasSuffix(dataPath, ".txt") || strings.HasSuffix(dataPath, ".csv"):
		src = newFileSources(nil, []string{dataPath}, nil)
	default:
		src = newHTTPSources(
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

	var whitelist, inbound, outbound atomic.Pointer[ipcohort.Cohort]

	if err := src.Init(false); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := reload(src, &whitelist, &inbound, &outbound); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		size(&inbound), size(&outbound))

	// Keep data fresh in the background if running as a daemon.
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go run(ctx, src, &whitelist, &inbound, &outbound)

	blockedInbound := containsInbound(ipStr, &whitelist, &inbound)
	blockedOutbound := containsOutbound(ipStr, &whitelist, &outbound)

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

func reload(src *Sources,
	whitelist, inbound, outbound *atomic.Pointer[ipcohort.Cohort],
) error {
	if wl, err := src.LoadWhitelist(); err != nil {
		return err
	} else if wl != nil {
		whitelist.Store(wl)
	}
	if in, err := src.LoadInbound(); err != nil {
		return err
	} else if in != nil {
		inbound.Store(in)
	}
	if out, err := src.LoadOutbound(); err != nil {
		return err
	} else if out != nil {
		outbound.Store(out)
	}
	return nil
}

func run(ctx context.Context, src *Sources,
	whitelist, inbound, outbound *atomic.Pointer[ipcohort.Cohort],
) {
	ticker := time.NewTicker(47 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			updated, err := src.Fetch(false)
			if err != nil {
				fmt.Fprintf(os.Stderr, "error: sync: %v\n", err)
				continue
			}
			if !updated {
				continue
			}
			if err := reload(src, whitelist, inbound, outbound); err != nil {
				fmt.Fprintf(os.Stderr, "error: reload: %v\n", err)
				continue
			}
			fmt.Fprintf(os.Stderr, "reloaded: inbound=%d outbound=%d\n",
				size(inbound), size(outbound))
		case <-ctx.Done():
			return
		}
	}
}

func containsInbound(ip string, whitelist, inbound *atomic.Pointer[ipcohort.Cohort]) bool {
	if wl := whitelist.Load(); wl != nil && wl.Contains(ip) {
		return false
	}
	c := inbound.Load()
	return c != nil && c.Contains(ip)
}

func containsOutbound(ip string, whitelist, outbound *atomic.Pointer[ipcohort.Cohort]) bool {
	if wl := whitelist.Load(); wl != nil && wl.Contains(ip) {
		return false
	}
	c := outbound.Load()
	return c != nil && c.Contains(ip)
}

func size(ptr *atomic.Pointer[ipcohort.Cohort]) int {
	if c := ptr.Load(); c != nil {
		return c.Size()
	}
	return 0
}
