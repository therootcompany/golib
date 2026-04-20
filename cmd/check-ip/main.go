package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

)

// inbound blocklist
const (
	inboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/single_ips.txt"
	inboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/networks.txt"
)

// outbound blocklist
const (
	outboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/single_ips.txt"
	outboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/networks.txt"
)

func defaultBlocklistDir() string {
	base, err := os.UserCacheDir()
	if err != nil {
		return os.Getenv("HOME") + "/.cache/bitwire-it"
	}
	return base + "/bitwire-it"
}

func main() {
	dataDir := flag.String("data-dir", "", "blocklist cache dir (default ~/.cache/bitwire-it)")
	cityDBPath := flag.String("city-db", "", "path to GeoLite2-City.mmdb (overrides -geoip-conf)")
	asnDBPath := flag.String("asn-db", "", "path to GeoLite2-ASN.mmdb (overrides -geoip-conf)")
	geoipConf := flag.String("geoip-conf", "", "path to GeoIP.conf; auto-downloads City+ASN into data-dir")
	gitURL := flag.String("git", "", "clone/pull blocklist from this git URL into data-dir")
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <ip-address>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  Blocklists are fetched via HTTP by default (use -git for git source).\n")
		fmt.Fprintf(os.Stderr, "  Pass a .txt/.csv path as the first arg to load a single local file.\n")
		flag.PrintDefaults()
	}
	flag.Parse()

	if flag.NArg() < 1 {
		flag.Usage()
		os.Exit(1)
	}

	// First arg is either a local file or the IP to check.
	var dataPath, ipStr string
	if flag.NArg() >= 2 || strings.HasSuffix(flag.Arg(0), ".txt") || strings.HasSuffix(flag.Arg(0), ".csv") {
		dataPath = flag.Arg(0)
		ipStr = flag.Arg(1)
	} else {
		ipStr = flag.Arg(0)
	}
	if *dataDir != "" {
		dataPath = *dataDir
	}
	if dataPath == "" {
		dataPath = defaultBlocklistDir()
	}

	// -- Blocklist ----------------------------------------------------------

	var src *Sources
	switch {
	case *gitURL != "":
		src = newGitSources(*gitURL, dataPath,
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

	blGroup, whitelist, inbound, outbound := src.Datasets()
	if err := blGroup.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		cohortSize(inbound), cohortSize(outbound))

	// -- GeoIP (optional) --------------------------------------------------

	geo, err := setupGeo(*geoipConf, *cityDBPath, *asnDBPath)
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

	blockedIn := isBlocked(ipStr, whitelist, inbound)
	blockedOut := isBlocked(ipStr, whitelist, outbound)

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
