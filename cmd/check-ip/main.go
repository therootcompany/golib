package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/therootcompany/golib/net/dataset"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
)

const (
	inboundSingleURL   = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/single_ips.txt"
	inboundNetworkURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/inbound/networks.txt"
	outboundSingleURL  = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/single_ips.txt"
	outboundNetworkURL = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables/outbound/networks.txt"
)

func main() {
	dataDir   := flag.String("data-dir", "", "blacklist cache dir (default ~/.cache/bitwire-it)")
	gitURL    := flag.String("git", "", "git URL to clone/pull blacklist from")
	whitelist := flag.String("whitelist", "", "path to whitelist file")
	inbound   := flag.String("inbound", "", "comma-separated paths to inbound blacklist files")
	outbound  := flag.String("outbound", "", "comma-separated paths to outbound blacklist files")
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

	// -- Blacklist ----------------------------------------------------------

	var syncs dataset.MultiSyncer
	var inboundPaths, outboundPaths []string

	switch {
	case *inbound != "" || *outbound != "":
		inboundPaths = splitPaths(*inbound)
		outboundPaths = splitPaths(*outbound)

	case *gitURL != "":
		cacheDir := cacheDir(*dataDir, "bitwire-it")
		syncs = dataset.MultiSyncer{gitshallow.New(*gitURL, cacheDir, 1, "")}
		inboundPaths = []string{
			filepath.Join(cacheDir, "tables/inbound/single_ips.txt"),
			filepath.Join(cacheDir, "tables/inbound/networks.txt"),
		}
		outboundPaths = []string{
			filepath.Join(cacheDir, "tables/outbound/single_ips.txt"),
			filepath.Join(cacheDir, "tables/outbound/networks.txt"),
		}

	default:
		dir := cacheDir(*dataDir, "bitwire-it")
		inboundSingle  := filepath.Join(dir, "inbound_single_ips.txt")
		inboundNetwork := filepath.Join(dir, "inbound_networks.txt")
		outboundSingle  := filepath.Join(dir, "outbound_single_ips.txt")
		outboundNetwork := filepath.Join(dir, "outbound_networks.txt")
		syncs = dataset.MultiSyncer{
			httpcache.New(inboundSingleURL, inboundSingle),
			httpcache.New(inboundNetworkURL, inboundNetwork),
			httpcache.New(outboundSingleURL, outboundSingle),
			httpcache.New(outboundNetworkURL, outboundNetwork),
		}
		inboundPaths  = []string{inboundSingle, inboundNetwork}
		outboundPaths = []string{outboundSingle, outboundNetwork}
	}

	g := dataset.NewGroup(syncs)
	var whitelistDS *dataset.View[ipcohort.Cohort]
	if *whitelist != "" {
		paths := splitPaths(*whitelist)
		whitelistDS = dataset.Add(g, func() (*ipcohort.Cohort, error) { return ipcohort.LoadFiles(paths...) })
	}
	inboundDS  := dataset.Add(g, func() (*ipcohort.Cohort, error) { return ipcohort.LoadFiles(inboundPaths...) })
	outboundDS := dataset.Add(g, func() (*ipcohort.Cohort, error) { return ipcohort.LoadFiles(outboundPaths...) })

	if err := g.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "error: blacklist: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		inboundDS.Load().Size(), outboundDS.Load().Size())

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
	go g.Run(ctx, 47*time.Minute)
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

func isBlocked(ip string, whitelist, cohort *dataset.View[ipcohort.Cohort]) bool {
	if cohort == nil {
		return false
	}
	if whitelist != nil && whitelist.Load().Contains(ip) {
		return false
	}
	return cohort.Load().Contains(ip)
}

func cacheDir(override, sub string) string {
	if override != "" {
		return override
	}
	base, err := os.UserCacheDir()
	if err != nil {
		base = filepath.Join(os.Getenv("HOME"), ".cache")
	}
	return filepath.Join(base, sub)
}

func splitPaths(s string) []string {
	return strings.Split(s, ",")
}
