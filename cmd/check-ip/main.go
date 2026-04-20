// check-ip reports whether an IPv4 address appears in the bitwire-it
// inbound/outbound blocklists and, when configured, prints GeoIP info.
//
// Source selection (in order of precedence):
//
//   - --inbound / --outbound   use local files (no syncing)
//   - --git URL                shallow-clone a git repo of blocklists
//   - (default)                fetch raw blocklist files over HTTP with caching
//
// Cohorts are held in atomic.Pointers and hot-swapped on refresh so callers
// never see a partial view. A single goroutine reloads on a ticker.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
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

	var inbound, outbound atomic.Pointer[ipcohort.Cohort]

	refresh, err := buildRefresher(cfg, &inbound, &outbound)
	if err != nil {
		return false, err
	}
	if err := refresh(); err != nil {
		return false, fmt.Errorf("blacklist: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		inbound.Load().Size(), outbound.Load().Size())

	go tick(ctx, refreshInterval, "blacklist", refresh)

	whitelist, err := loadWhitelist(cfg.Whitelist)
	if err != nil {
		return false, fmt.Errorf("whitelist: %w", err)
	}

	geo, err := geoip.OpenDatabases(cfg.GeoIPConf, cfg.CityDB, cfg.ASNDB)
	if err != nil {
		return false, err
	}
	if err := geo.Init(); err != nil {
		return false, fmt.Errorf("geoip: %w", err)
	}
	geo.Run(ctx, refreshInterval)

	blockedIn := isBlocked(ipStr, whitelist, inbound.Load())
	blockedOut := isBlocked(ipStr, whitelist, outbound.Load())

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

// buildRefresher wires the chosen source (files/git/http) to the inbound and
// outbound atomic pointers, and returns a function that performs one refresh
// cycle: fetch upstream, and if anything changed (or on the first call),
// reload both cohorts and atomically swap them in.
func buildRefresher(
	cfg Config,
	inbound, outbound *atomic.Pointer[ipcohort.Cohort],
) (func() error, error) {
	loadAndSwap := func(inPaths, outPaths []string) error {
		in, err := ipcohort.LoadFiles(inPaths...)
		if err != nil {
			return fmt.Errorf("inbound: %w", err)
		}
		out, err := ipcohort.LoadFiles(outPaths...)
		if err != nil {
			return fmt.Errorf("outbound: %w", err)
		}
		inbound.Store(in)
		outbound.Store(out)
		return nil
	}

	switch {
	case cfg.Inbound != "" || cfg.Outbound != "":
		inPaths, outPaths := splitCSV(cfg.Inbound), splitCSV(cfg.Outbound)
		loaded := false
		return func() error {
			if loaded {
				return nil
			}
			loaded = true
			return loadAndSwap(inPaths, outPaths)
		}, nil

	case cfg.GitURL != "":
		dir, err := cacheDir(cfg.DataDir)
		if err != nil {
			return nil, err
		}
		repo := gitshallow.New(cfg.GitURL, dir, 1, "")
		inPaths := []string{
			repo.FilePath("tables/inbound/single_ips.txt"),
			repo.FilePath("tables/inbound/networks.txt"),
		}
		outPaths := []string{
			repo.FilePath("tables/outbound/single_ips.txt"),
			repo.FilePath("tables/outbound/networks.txt"),
		}
		first := true
		return func() error {
			updated, err := repo.Sync()
			if err != nil {
				return err
			}
			if !first && !updated {
				return nil
			}
			first = false
			return loadAndSwap(inPaths, outPaths)
		}, nil

	default:
		dir, err := cacheDir(cfg.DataDir)
		if err != nil {
			return nil, err
		}
		cachers := []*httpcache.Cacher{
			httpcache.New(bitwireRawBase+"/inbound/single_ips.txt", filepath.Join(dir, "inbound_single_ips.txt")),
			httpcache.New(bitwireRawBase+"/inbound/networks.txt", filepath.Join(dir, "inbound_networks.txt")),
			httpcache.New(bitwireRawBase+"/outbound/single_ips.txt", filepath.Join(dir, "outbound_single_ips.txt")),
			httpcache.New(bitwireRawBase+"/outbound/networks.txt", filepath.Join(dir, "outbound_networks.txt")),
		}
		inPaths := []string{cachers[0].Path, cachers[1].Path}
		outPaths := []string{cachers[2].Path, cachers[3].Path}
		first := true
		return func() error {
			var anyUpdated bool
			for _, c := range cachers {
				u, err := c.Fetch()
				if err != nil {
					return err
				}
				anyUpdated = anyUpdated || u
			}
			if !first && !anyUpdated {
				return nil
			}
			first = false
			return loadAndSwap(inPaths, outPaths)
		}, nil
	}
}

// tick calls fn every interval until ctx is done. Errors are logged, not fatal.
func tick(ctx context.Context, interval time.Duration, name string, fn func() error) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := fn(); err != nil {
				fmt.Fprintf(os.Stderr, "%s: refresh error: %v\n", name, err)
			}
		}
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
