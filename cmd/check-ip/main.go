// check-ip runs an HTTP API that reports whether an IP appears in the
// configured blocklist repo and, when GeoIP.conf is available, enriches
// the response with MaxMind GeoLite2 City + ASN data.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/dataset"
)

const (
	defaultBlocklistRepo = "https://github.com/bitwire-it/ipblocklist.git"
	refreshInterval      = 47 * time.Minute
)

type Config struct {
	Serve         string
	GeoIPConf     string
	BlocklistRepo string
	CacheDir      string
}

func main() {
	cfg := Config{}

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.Serve, "serve", "", "bind address for the HTTP API, e.g. :8080")
	fs.StringVar(&cfg.GeoIPConf, "geoip-conf", "", "path to GeoIP.conf (default: ./GeoIP.conf or ~/.config/maxmind/GeoIP.conf)")
	fs.StringVar(&cfg.BlocklistRepo, "blocklist-repo", defaultBlocklistRepo, "git URL of the blocklist repo (must match bitwire-it layout)")
	fs.StringVar(&cfg.CacheDir, "cache-dir", "", "cache parent dir, holds bitwire-it/ and maxmind/ subdirs (default: OS user cache)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --serve <bind> [flags]\n", os.Args[0])
		fs.PrintDefaults()
	}
	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		os.Exit(1)
	}
	if cfg.Serve == "" {
		fs.Usage()
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	cacheDir := cfg.CacheDir
	if cacheDir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			fatal("cache-dir", err)
		}
		cacheDir = base
	}

	// Blocklists: one git repo, two views sharing the same pull.
	repo := gitshallow.New(cfg.BlocklistRepo, filepath.Join(cacheDir, "bitwire-it"), 1, "")
	group := dataset.NewGroup(repo)
	inbound := dataset.Add(group, loadCohort(
		repo.FilePath("tables/inbound/single_ips.txt"),
		repo.FilePath("tables/inbound/networks.txt"),
	))
	outbound := dataset.Add(group, loadCohort(
		repo.FilePath("tables/outbound/single_ips.txt"),
		repo.FilePath("tables/outbound/networks.txt"),
	))
	if err := group.Load(ctx); err != nil {
		fatal("blocklists", err)
	}
	go group.Tick(ctx, refreshInterval, func(err error) {
		fmt.Fprintf(os.Stderr, "refresh: %v\n", err)
	})

	// GeoIP: city + ASN readers, downloaded via httpcache when GeoIP.conf
	// is available; otherwise read from disk at the cache paths.
	maxmindDir := filepath.Join(cacheDir, "maxmind")
	geo, err := geoip.OpenDatabases(
		cfg.GeoIPConf,
		filepath.Join(maxmindDir, geoip.CityEdition+".mmdb"),
		filepath.Join(maxmindDir, geoip.ASNEdition+".mmdb"),
	)
	if err != nil {
		fatal("geoip", err)
	}
	defer func() { _ = geo.Close() }()

	checker := &Checker{Inbound: inbound, Outbound: outbound, GeoIP: geo}
	if err := serve(ctx, cfg.Serve, checker); err != nil {
		fatal("serve", err)
	}
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "error: %s: %v\n", what, err)
	os.Exit(1)
}

// Checker bundles the blocklist views with the optional GeoIP databases.
type Checker struct {
	Inbound  *dataset.View[ipcohort.Cohort]
	Outbound *dataset.View[ipcohort.Cohort]
	GeoIP    *geoip.Databases
}

// Result is the structured verdict for a single IP.
type Result struct {
	IP              string     `json:"ip"`
	Blocked         bool       `json:"blocked"`
	BlockedInbound  bool       `json:"blocked_inbound"`
	BlockedOutbound bool       `json:"blocked_outbound"`
	Geo             geoip.Info `json:"geo,omitzero"`
}

// Check returns the structured verdict for ip.
func (c *Checker) Check(ip string) Result {
	in := contains(c.Inbound.Value(), ip)
	out := contains(c.Outbound.Value(), ip)
	return Result{
		IP:              ip,
		Blocked:         in || out,
		BlockedInbound:  in,
		BlockedOutbound: out,
		Geo:             c.GeoIP.Lookup(ip),
	}
}

func contains(c *ipcohort.Cohort, ip string) bool {
	return c != nil && c.Contains(ip)
}

func loadCohort(paths ...string) func() (*ipcohort.Cohort, error) {
	return func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(paths...)
	}
}
