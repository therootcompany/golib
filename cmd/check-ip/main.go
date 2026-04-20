package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/therootcompany/golib/net/dataset"
	"github.com/therootcompany/golib/net/geoip"
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

type CheckIPConfig struct {
	DataDir   string
	GitURL    string
	Whitelist string
	Inbound   string
	Outbound  string
	GeoIPConf string
	CityDB    string
	ASNDB     string
}

func main() {
	cfg := CheckIPConfig{}

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.DataDir,   "data-dir",  "", "blacklist cache dir (default ~/.cache/bitwire-it)")
	fs.StringVar(&cfg.GitURL,    "git",        "", "git URL to clone/pull blacklist from")
	fs.StringVar(&cfg.Whitelist, "whitelist",  "", "path to whitelist file")
	fs.StringVar(&cfg.Inbound,   "inbound",   "", "comma-separated paths to inbound blacklist files")
	fs.StringVar(&cfg.Outbound,  "outbound",  "", "comma-separated paths to outbound blacklist files")
	fs.StringVar(&cfg.GeoIPConf, "geoip-conf", "", "path to GeoIP.conf (auto-discovered if absent)")
	fs.StringVar(&cfg.CityDB,    "city-db",    "", "path to GeoLite2-City.mmdb (skips auto-download)")
	fs.StringVar(&cfg.ASNDB,     "asn-db",     "", "path to GeoLite2-ASN.mmdb (skips auto-download)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <ip-address>\n", os.Args[0])
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			fmt.Fprintf(os.Stdout, "check-ip\n")
			os.Exit(0)
		case "help", "-help", "--help":
			fmt.Fprintf(os.Stdout, "check-ip\n\n")
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	ipStr := fs.Arg(0)

	// -- Blacklist ----------------------------------------------------------

	var (
		syncer        dataset.Syncer
		inboundPaths  []string
		outboundPaths []string
	)

	switch {
	case cfg.Inbound != "" || cfg.Outbound != "":
		syncer         = dataset.NopSyncer{}
		inboundPaths   = splitPaths(cfg.Inbound)
		outboundPaths  = splitPaths(cfg.Outbound)

	case cfg.GitURL != "":
		dir := cacheDir(cfg.DataDir, "bitwire-it")
		gr  := gitshallow.New(cfg.GitURL, dir, 1, "")
		syncer         = gr
		inboundPaths   = []string{gr.FilePath("tables/inbound/single_ips.txt"), gr.FilePath("tables/inbound/networks.txt")}
		outboundPaths  = []string{gr.FilePath("tables/outbound/single_ips.txt"), gr.FilePath("tables/outbound/networks.txt")}

	default:
		dir        := cacheDir(cfg.DataDir, "bitwire-it")
		inSingle   := httpcache.New(inboundSingleURL,   filepath.Join(dir, "inbound_single_ips.txt"))
		inNetwork  := httpcache.New(inboundNetworkURL,  filepath.Join(dir, "inbound_networks.txt"))
		outSingle  := httpcache.New(outboundSingleURL,  filepath.Join(dir, "outbound_single_ips.txt"))
		outNetwork := httpcache.New(outboundNetworkURL, filepath.Join(dir, "outbound_networks.txt"))
		syncer        = dataset.MultiSyncer{inSingle, inNetwork, outSingle, outNetwork}
		inboundPaths  = []string{inSingle.Path, inNetwork.Path}
		outboundPaths = []string{outSingle.Path, outNetwork.Path}
	}

	g          := dataset.NewGroup(syncer)
	inboundDS  := dataset.Add(g, loadCohort(inboundPaths...))
	outboundDS := dataset.Add(g, loadCohort(outboundPaths...))

	if err := g.Init(); err != nil {
		fmt.Fprintf(os.Stderr, "error: blacklist: %v\n", err)
		os.Exit(1)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		inboundDS.Load().Size(), outboundDS.Load().Size())

	var whitelistDS *dataset.Dataset[ipcohort.Cohort]
	if cfg.Whitelist != "" {
		whitelistDS = dataset.New(dataset.NopSyncer{}, loadCohort(splitPaths(cfg.Whitelist)...))
		if err := whitelistDS.Init(); err != nil {
			fmt.Fprintf(os.Stderr, "error: whitelist: %v\n", err)
			os.Exit(1)
		}
	}

	// -- GeoIP (optional) --------------------------------------------------

	geo, err := geoip.OpenDatabases(cfg.GeoIPConf, cfg.CityDB, cfg.ASNDB)
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

func loadCohort(paths ...string) func() (*ipcohort.Cohort, error) {
	return func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(paths...)
	}
}

func isBlocked(ip string, whitelist, cohort *dataset.Dataset[ipcohort.Cohort]) bool {
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
