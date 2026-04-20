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
	Bind     string
	ConfPath string
	RepoURL  string
	CacheDir string

	inbound  *dataset.View[ipcohort.Cohort]
	outbound *dataset.View[ipcohort.Cohort]
	geo      *dataset.View[geoip.Databases]
}

func printVersion(w *os.File) {
	fmt.Fprintf(w, "check-ip %s\n", version)
}

func main() {
	cfg := IPCheck{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.Bind, "serve", "", "bind address for the HTTP API, e.g. :8080")
	fs.StringVar(&cfg.ConfPath, "geoip-conf", "", "path to GeoIP.conf (default: ./GeoIP.conf or ~/.config/maxmind/GeoIP.conf)")
	fs.StringVar(&cfg.RepoURL, "blocklist-repo", defaultBlocklistRepo, "git URL of the blocklist repo (must match bitwire-it layout)")
	fs.StringVar(&cfg.CacheDir, "cache-dir", "", "cache parent dir, holds bitwire-it/ and maxmind/ subdirs (default: OS user cache)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s --serve <bind> [flags]\n", os.Args[0])
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			fmt.Fprintln(os.Stdout, "")
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

	maxmind := filepath.Join(cfg.CacheDir, "maxmind")
	geoGroup := dataset.NewGroup(geoFetcher(cfg.ConfPath, maxmind))
	cfg.geo = dataset.Add(geoGroup, func() (*geoip.Databases, error) {
		return geoip.Open(maxmind)
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

// geoFetcher returns a Fetcher for the GeoLite2 City + ASN .mmdb files.
// With a GeoIP.conf (explicit path or auto-discovered) both files are
// downloaded via httpcache conditional GETs; otherwise the files are
// expected to exist on disk and are polled for out-of-band changes.
func geoFetcher(confPath, dir string) dataset.Fetcher {
	cityPath := filepath.Join(dir, geoip.CityEdition+".mmdb")
	asnPath := filepath.Join(dir, geoip.ASNEdition+".mmdb")
	if confPath == "" {
		for _, p := range geoip.DefaultConfPaths() {
			if _, err := os.Stat(p); err == nil {
				confPath = p
				break
			}
		}
	}
	if confPath == "" {
		return dataset.PollFiles(cityPath, asnPath)
	}
	conf, err := geoip.ParseConf(confPath)
	if err != nil {
		log.Fatalf("geoip-conf: %v", err)
	}
	dl := geoip.New(conf.AccountID, conf.LicenseKey)
	city := dl.NewCacher(geoip.CityEdition, cityPath)
	asn := dl.NewCacher(geoip.ASNEdition, asnPath)
	return dataset.FetcherFunc(func() (bool, error) {
		cityUpdated, err := city.Fetch()
		if err != nil {
			return false, fmt.Errorf("fetch %s: %w", geoip.CityEdition, err)
		}
		asnUpdated, err := asn.Fetch()
		if err != nil {
			return false, fmt.Errorf("fetch %s: %w", geoip.ASNEdition, err)
		}
		return cityUpdated || asnUpdated, nil
	})
}
