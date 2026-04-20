package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

// Default HTTP sources for the bitwire-it blocklist.
const (
	inboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/single_ips.txt"
	inboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/networks.txt"
	outboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/single_ips.txt"
	outboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/networks.txt"
)

func defaultCacheDir(sub string) string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	return filepath.Join(base, sub)
}

func main() {
	// Blocklist source flags — all optional; defaults pull from bitwire-it via HTTP.
	dataDir   := flag.String("data-dir", "", "blocklist cache dir (default ~/.cache/bitwire-it)")
	gitURL    := flag.String("git", "", "git URL to clone/pull blocklist from (alternative to HTTP)")
	whitelist := flag.String("whitelist", "", "path to whitelist file (overrides block)")
	inbound   := flag.String("inbound", "", "comma-separated paths to inbound blocklist files")
	outbound  := flag.String("outbound", "", "comma-separated paths to outbound blocklist files")

	// GeoIP flags — auto-discovered from ./GeoIP.conf or ~/.config/maxmind/GeoIP.conf.
	geoipConf := flag.String("geoip-conf", "", "path to GeoIP.conf (auto-discovered if absent)")
	cityDB    := flag.String("city-db", "", "path to GeoLite2-City.mmdb (skips auto-download)")
	asnDB     := flag.String("asn-db", "", "path to GeoLite2-ASN.mmdb (skips auto-download)")

	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <ip-address>\n", os.Args[0])
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() != 1 {
		flag.Usage()
		os.Exit(1)
	}
	ipStr := flag.Arg(0)

	// -- Blocklist ----------------------------------------------------------

	src := buildSources(*gitURL, *dataDir, *whitelist, *inbound, *outbound)
	blGroup, whitelistDS, inboundDS, outboundDS := src.Datasets()
	if err := blGroup.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "error: blocklist: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		cohortSize(inboundDS), cohortSize(outboundDS))

	// -- GeoIP (optional) --------------------------------------------------

	geo, err := setupGeo(*geoipConf, *cityDB, *asnDB)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if err := geo.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "error: geoip: %v\n", err)
		os.Exit(1)
	}

	// -- Background refresh ------------------------------------------------

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go blGroup.Run(ctx, 47*time.Minute)
	geo.Run(ctx, 47*time.Minute)

	// -- Check and report --------------------------------------------------

	blockedIn  := isBlocked(ipStr, whitelistDS, inboundDS)
	blockedOut := isBlocked(ipStr, whitelistDS, outboundDS)

	switch {
	case blockedIn && blockedOut:
		fmt.Printf("%s is BLOCKED (inbound + outbound)\n", ipStr)
	case blockedIn:
		fmt.Printf("%s is BLOCKED (inbound)\n", ipStr)
	case blockedOut:
		fmt.Printf("%s is BLOCKED (outbound)\n", ipStr)
	default:
		fmt.Printf("%s is allowed\n", ipStr)
	}
	geo.PrintInfo(os.Stdout, ipStr)

	if blockedIn || blockedOut {
		os.Exit(1)
	}
}
