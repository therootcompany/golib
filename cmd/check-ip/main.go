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
	"net/http"
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
	WhitelistPath string

	// GeoIPBasicAuth is the pre-encoded Authorization header value for
	// MaxMind downloads.
	GeoIPBasicAuth string

	inbound   *dataset.View[ipcohort.Cohort]
	outbound  *dataset.View[ipcohort.Cohort]
	whitelist *dataset.View[ipcohort.Cohort]
	geo       *dataset.View[geoip.Databases]
}

func main() {
	cfg := IPCheck{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.Bind, "serve", "", "bind address for the HTTP API, e.g. :8080")
	fs.StringVar(&cfg.GeoIPConfPath, "geoip-conf", "", "path to GeoIP.conf with MaxMind AccountID + LicenseKey\n(free signup at https://www.maxmind.com/en/geolite2/signup)\n(default: ./GeoIP.conf or ~/.config/maxmind/GeoIP.conf)")
	fs.StringVar(&cfg.RepoURL, "blocklist-repo", defaultBlocklistRepo, "git URL of the blocklist repo (must match bitwire-it layout)")
	fs.StringVar(&cfg.CacheDir, "cache-dir", "", "cache parent dir, holds bitwire-it/ and maxmind/ subdirs (default: OS user cache)")
	fs.StringVar(&cfg.WhitelistPath, "whitelist", "", "path to a file of IPs and/or CIDRs (one per line) that override block decisions")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <ip> [ip...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s --serve <bind> [flags]\n", os.Args[0])
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
	ips := fs.Args()
	if cfg.Bind == "" && len(ips) == 0 {
		fmt.Fprintln(os.Stderr, "error: provide at least one IP argument or --serve <bind>")
		fs.Usage()
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
		data, err := os.ReadFile(cfg.GeoIPConfPath)
		if err != nil {
			log.Fatalf("geoip-conf: %v", err)
		}
		conf, err := geoip.ParseConf(string(data))
		if err != nil {
			log.Fatalf("geoip-conf: %v", err)
		}
		cfg.GeoIPBasicAuth = httpcache.BasicAuth(conf.AccountID, conf.LicenseKey)
	}

	// Blocklists: git repo with inbound + outbound IP cohort files.
	repo := gitshallow.New(cfg.RepoURL, filepath.Join(cfg.CacheDir, "bitwire-it"), 1, "")
	blocklists := dataset.NewSet(repo)
	cfg.inbound = dataset.Add(blocklists, func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/inbound/single_ips.txt"),
			repo.FilePath("tables/inbound/networks.txt"),
		)
	})
	cfg.outbound = dataset.Add(blocklists, func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/outbound/single_ips.txt"),
			repo.FilePath("tables/outbound/networks.txt"),
		)
	})
	if err := blocklists.Load(context.Background()); err != nil {
		log.Fatalf("blocklists: %v", err)
	}

	// GeoIP: download the City + ASN tar.gz archives via httpcache
	// conditional GETs. geoip.Open extracts in-memory — no .mmdb files
	// are written to disk.
	if cfg.GeoIPBasicAuth == "" {
		log.Fatalf("geoip-conf: not found; set --geoip-conf or place GeoIP.conf in a default location.\n"+
			"GeoLite2 registration and the AccountID/LicenseKey needed for GeoIP.conf are free at:\n"+
			"  https://www.maxmind.com/en/geolite2/signup\n"+
			"Then create a license key and write ./GeoIP.conf (or ~/.config/maxmind/GeoIP.conf):\n"+
			"  AccountID   <your-account-id>\n"+
			"  LicenseKey  <your-license-key>\n"+
			"  EditionIDs  GeoLite2-City GeoLite2-ASN\n"+
			"Default search paths: %v", geoip.DefaultConfPaths())
	}
	maxmindDir := filepath.Join(cfg.CacheDir, "maxmind")
	authHeader := http.Header{"Authorization": []string{cfg.GeoIPBasicAuth}}
	geoSet := dataset.NewSet(
		&httpcache.Cacher{
			URL:    geoip.DownloadBase + "/GeoLite2-City/download?suffix=tar.gz",
			Path:   filepath.Join(maxmindDir, "GeoLite2-City.tar.gz"),
			MaxAge: 3 * 24 * time.Hour,
			Header: authHeader,
		},
		&httpcache.Cacher{
			URL:    geoip.DownloadBase + "/GeoLite2-ASN/download?suffix=tar.gz",
			Path:   filepath.Join(maxmindDir, "GeoLite2-ASN.tar.gz"),
			MaxAge: 3 * 24 * time.Hour,
			Header: authHeader,
		},
	)
	cfg.geo = dataset.Add(geoSet, func() (*geoip.Databases, error) {
		return geoip.Open(maxmindDir)
	})
	if err := geoSet.Load(context.Background()); err != nil {
		log.Fatalf("geoip: %v", err)
	}
	defer func() { _ = cfg.geo.Value().Close() }()

	// Whitelist: combined IPs + CIDRs in one file, polled for mtime changes.
	// A match here overrides any block decision from the blocklists.
	var whitelistSet *dataset.Set
	if cfg.WhitelistPath != "" {
		whitelistSet = dataset.NewSet(dataset.PollFiles(cfg.WhitelistPath))
		cfg.whitelist = dataset.Add(whitelistSet, func() (*ipcohort.Cohort, error) {
			return ipcohort.LoadFile(cfg.WhitelistPath)
		})
		if err := whitelistSet.Load(context.Background()); err != nil {
			log.Fatalf("whitelist: %v", err)
		}
	}

	for _, ip := range ips {
		cfg.writeText(os.Stdout, cfg.lookup(ip))
	}
	if cfg.Bind == "" {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	go blocklists.Tick(ctx, refreshInterval, func(err error) {
		log.Printf("blocklists refresh: %v", err)
	})
	go geoSet.Tick(ctx, refreshInterval, func(err error) {
		log.Printf("geoip refresh: %v", err)
	})
	if whitelistSet != nil {
		go whitelistSet.Tick(ctx, refreshInterval, func(err error) {
			log.Printf("whitelist refresh: %v", err)
		})
	}
	if err := cfg.serve(ctx); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
