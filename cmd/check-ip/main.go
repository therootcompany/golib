// check-ip reports whether an IPv4 address appears in the bitwire-it
// inbound/outbound blocklists and, when configured, prints GeoIP info.
//
// Source selection (in order of precedence):
//
//   - --inbound / --outbound   use local files (no syncing)
//   - --git URL                shallow-clone a git repo of blocklists
//   - (default)                fetch raw blocklist files over HTTP with caching
//
// Each mode builds a sync/dataset.Group: one Fetcher shared by the inbound
// and outbound views, so a single git pull (or HTTP-304 cycle) drives both.
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

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/dataset"
)

const (
	bitwireGitURL  = "https://github.com/bitwire-it/ipblocklist.git"
	bitwireRawBase = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables"

	refreshInterval = 47 * time.Minute
)

type Config struct {
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
	cfg := Config{}

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.DataDir, "data-dir", "", "blacklist cache dir (default ~/.cache/bitwire-it)")
	fs.StringVar(&cfg.GitURL, "git", "", "git URL to clone/pull blacklist from (e.g. "+bitwireGitURL+")")
	fs.StringVar(&cfg.Whitelist, "whitelist", "", "comma-separated paths to whitelist files")
	fs.StringVar(&cfg.Inbound, "inbound", "", "comma-separated paths to inbound blacklist files")
	fs.StringVar(&cfg.Outbound, "outbound", "", "comma-separated paths to outbound blacklist files")
	fs.StringVar(&cfg.GeoIPConf, "geoip-conf", "", "path to GeoIP.conf (auto-discovered if absent)")
	fs.StringVar(&cfg.CityDB, "city-db", "", "path to GeoLite2-City.mmdb (skips auto-download)")
	fs.StringVar(&cfg.ASNDB, "asn-db", "", "path to GeoLite2-ASN.mmdb (skips auto-download)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <ip-address>\n", os.Args[0])
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			fmt.Fprintln(os.Stdout, "check-ip")
			os.Exit(0)
		case "help", "-help", "--help":
			fmt.Fprintln(os.Stdout, "check-ip")
			fmt.Fprintln(os.Stdout)
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

	blocked, err := run(cfg, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if blocked {
		os.Exit(1)
	}
}

func run(cfg Config, ipStr string) (blocked bool, err error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	group, inbound, outbound, err := newBlocklistGroup(cfg)
	if err != nil {
		return false, err
	}
	if err := group.Load(ctx); err != nil {
		return false, fmt.Errorf("blacklist: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		inbound.Value().Size(), outbound.Value().Size())
	go group.Tick(ctx, refreshInterval)

	whitelist, err := loadWhitelist(cfg.Whitelist)
	if err != nil {
		return false, fmt.Errorf("whitelist: %w", err)
	}

	geo, err := geoip.OpenDatabases(cfg.GeoIPConf, cfg.CityDB, cfg.ASNDB)
	if err != nil {
		return false, fmt.Errorf("geoip: %w", err)
	}
	defer func() { _ = geo.Close() }()

	blockedIn := isBlocked(ipStr, whitelist, inbound.Value())
	blockedOut := isBlocked(ipStr, whitelist, outbound.Value())

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

	return blockedIn || blockedOut, nil
}

// newBlocklistGroup wires a dataset.Group to the configured source (local
// files, git, or HTTP-cached raw files) and registers inbound/outbound views.
func newBlocklistGroup(cfg Config) (
	_ *dataset.Group,
	inbound, outbound *dataset.View[ipcohort.Cohort],
	err error,
) {
	fetcher, inPaths, outPaths, err := newFetcher(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	g := dataset.NewGroup(fetcher)
	inbound = dataset.Add(g, loadCohort(inPaths))
	outbound = dataset.Add(g, loadCohort(outPaths))
	return g, inbound, outbound, nil
}

// newFetcher picks a Fetcher based on cfg and returns the on-disk file paths
// each view should parse after a sync.
func newFetcher(cfg Config) (fetcher dataset.Fetcher, inPaths, outPaths []string, err error) {
	switch {
	case cfg.Inbound != "" || cfg.Outbound != "":
		return dataset.NopFetcher{}, splitCSV(cfg.Inbound), splitCSV(cfg.Outbound), nil

	case cfg.GitURL != "":
		dir, err := cacheDir(cfg.DataDir)
		if err != nil {
			return nil, nil, nil, err
		}
		repo := gitshallow.New(cfg.GitURL, dir, 1, "")
		return repo,
			[]string{
				repo.FilePath("tables/inbound/single_ips.txt"),
				repo.FilePath("tables/inbound/networks.txt"),
			},
			[]string{
				repo.FilePath("tables/outbound/single_ips.txt"),
				repo.FilePath("tables/outbound/networks.txt"),
			},
			nil

	default:
		dir, err := cacheDir(cfg.DataDir)
		if err != nil {
			return nil, nil, nil, err
		}
		cachers := []*httpcache.Cacher{
			httpcache.New(bitwireRawBase+"/inbound/single_ips.txt", filepath.Join(dir, "inbound_single_ips.txt")),
			httpcache.New(bitwireRawBase+"/inbound/networks.txt", filepath.Join(dir, "inbound_networks.txt")),
			httpcache.New(bitwireRawBase+"/outbound/single_ips.txt", filepath.Join(dir, "outbound_single_ips.txt")),
			httpcache.New(bitwireRawBase+"/outbound/networks.txt", filepath.Join(dir, "outbound_networks.txt")),
		}
		return dataset.FetcherFunc(func() (bool, error) {
				var any bool
				for _, c := range cachers {
					u, err := c.Fetch()
					if err != nil {
						return false, err
					}
					any = any || u
				}
				return any, nil
			}),
			[]string{cachers[0].Path, cachers[1].Path},
			[]string{cachers[2].Path, cachers[3].Path},
			nil
	}
}

func loadCohort(paths []string) func() (*ipcohort.Cohort, error) {
	return func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(paths...)
	}
}

func loadWhitelist(paths string) (*ipcohort.Cohort, error) {
	if paths == "" {
		return nil, nil
	}
	return ipcohort.LoadFiles(strings.Split(paths, ",")...)
}

func cacheDir(override string) (string, error) {
	if override != "" {
		return override, nil
	}
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(base, "bitwire-it"), nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}

func isBlocked(ip string, whitelist, cohort *ipcohort.Cohort) bool {
	if cohort == nil {
		return false
	}
	if whitelist != nil && whitelist.Contains(ip) {
		return false
	}
	return cohort.Contains(ip)
}
