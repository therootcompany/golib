// check-ip runs an HTTP API that reports whether an IP appears in the
// configured blocklist repo and enriches the response with MaxMind
// GeoLite2 City + ASN data.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/dataset"
)

const (
	defaultBlocklistRepo = "https://github.com/bitwire-it/ipblocklist.git"
	refreshInterval      = 47 * time.Minute
	version              = "dev"
)

// IPCheck holds the parsed CLI config and the loaded data sources used by
// the HTTP handler.
type IPCheck struct {
	Bind          string
	GeoIPConfPath string
	RepoURL       string
	CacheDir      string

	// GeoIPBasicAuth is the pre-encoded Authorization header value for
	// MaxMind downloads. Empty when no GeoIP.conf was found — in that case
	// the .tar.gz archives must already exist in <CacheDir>/maxmind/.
	GeoIPBasicAuth string

	inbound  *dataset.View[ipcohort.Cohort]
	outbound *dataset.View[ipcohort.Cohort]
	geo      *dataset.View[geoip.Databases]
}

func main() {
	cfg := IPCheck{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.Bind, "serve", "", "bind address for the HTTP API, e.g. :8080")
	fs.StringVar(&cfg.GeoIPConfPath, "geoip-conf", "", "path to GeoIP.conf (default: ./GeoIP.conf or ~/.config/maxmind/GeoIP.conf)")
	fs.StringVar(&cfg.RepoURL, "blocklist-repo", defaultBlocklistRepo, "git URL of the blocklist repo (must match bitwire-it layout)")
	fs.StringVar(&cfg.CacheDir, "cache-dir", "", "cache parent dir, holds bitwire-it/ and maxmind/ subdirs (default: OS user cache)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --serve <bind> [flags]\n", os.Args[0])
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			fmt.Fprintf(os.Stdout, "check-ip %s\n", version)
			os.Exit(0)
		case "help", "-help", "--help":
			fmt.Fprintf(os.Stdout, "check-ip %s\n\n", version)
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
	if cfg.CacheDir == "" {
		d, err := os.UserCacheDir()
		if err != nil {
			log.Fatalf("cache-dir: %v", err)
		}
		cfg.CacheDir = d
	}

	// GeoIP config discovery: explicit --geoip-conf wins; otherwise check the
	// default locations. If found, parse it and stash the basic-auth header
	// value for later MaxMind downloads.
	if cfg.GeoIPConfPath == "" {
		for _, p := range geoip.DefaultConfPaths() {
			if _, err := os.Stat(p); err == nil {
				cfg.GeoIPConfPath = p
				break
			}
		}
	}
	if cfg.GeoIPConfPath != "" {
		conf, err := geoip.ParseConf(cfg.GeoIPConfPath)
		if err != nil {
			log.Fatalf("geoip-conf: %v", err)
		}
		cfg.GeoIPBasicAuth = httpcache.BasicAuth(conf.AccountID, conf.LicenseKey)
	}

	// Blocklists: git repo with inbound + outbound IP cohort files.
	repo := gitshallow.New(cfg.RepoURL, filepath.Join(cfg.CacheDir, "bitwire-it"), 1, "")
	group := dataset.NewGroup(repo)
	cfg.inbound = dataset.Add(group, func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/inbound/single_ips.txt"),
			repo.FilePath("tables/inbound/networks.txt"),
		)
	})
	cfg.outbound = dataset.Add(group, func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/outbound/single_ips.txt"),
			repo.FilePath("tables/outbound/networks.txt"),
		)
	})
	if err := group.Load(context.Background()); err != nil {
		log.Fatalf("blocklists: %v", err)
	}

	// GeoIP: with credentials, download the City + ASN tar.gz archives via
	// httpcache conditional GETs. Without them, poll the existing tar.gz
	// files in maxmindDir. geoip.Open extracts in-memory — no .mmdb files
	// are written to disk.
	maxmindDir := filepath.Join(cfg.CacheDir, "maxmind")
	cityTarPath := filepath.Join(maxmindDir, "GeoLite2-City.tar.gz")
	asnTarPath := filepath.Join(maxmindDir, "GeoLite2-ASN.tar.gz")
	var geoFetcher dataset.Fetcher
	if cfg.GeoIPBasicAuth != "" {
		city := &httpcache.Cacher{
			URL:        geoip.DownloadBase + "/GeoLite2-City/download?suffix=tar.gz",
			Path:       cityTarPath,
			MaxAge:     3 * 24 * time.Hour,
			AuthHeader: "Authorization",
			AuthValue:  cfg.GeoIPBasicAuth,
		}
		asn := &httpcache.Cacher{
			URL:        geoip.DownloadBase + "/GeoLite2-ASN/download?suffix=tar.gz",
			Path:       asnTarPath,
			MaxAge:     3 * 24 * time.Hour,
			AuthHeader: "Authorization",
			AuthValue:  cfg.GeoIPBasicAuth,
		}
		geoFetcher = dataset.FetcherFunc(func() (bool, error) {
			cityUpdated, err := city.Fetch()
			if err != nil {
				return false, fmt.Errorf("fetch GeoLite2-City: %w", err)
			}
			asnUpdated, err := asn.Fetch()
			if err != nil {
				return false, fmt.Errorf("fetch GeoLite2-ASN: %w", err)
			}
			return cityUpdated || asnUpdated, nil
		})
	} else {
		geoFetcher = dataset.PollFiles(cityTarPath, asnTarPath)
	}
	geoGroup := dataset.NewGroup(geoFetcher)
	cfg.geo = dataset.Add(geoGroup, func() (*geoip.Databases, error) {
		return geoip.Open(maxmindDir)
	})
	if err := geoGroup.Load(context.Background()); err != nil {
		log.Fatalf("geoip: %v", err)
	}
	defer func() { _ = cfg.geo.Value().Close() }()

	if cfg.Bind == "" {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go group.Tick(ctx, refreshInterval, func(err error) {
		log.Printf("blocklists refresh: %v", err)
	})
	go geoGroup.Tick(ctx, refreshInterval, func(err error) {
		log.Printf("geoip refresh: %v", err)
	})
	if err := cfg.serve(ctx); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
