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

func main() {
	var (
		bind     string
		confPath string
		repoURL  string
		cacheDir string
	)
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&bind, "serve", "", "bind address for the HTTP API, e.g. :8080")
	fs.StringVar(&confPath, "geoip-conf", "", "path to GeoIP.conf (default: ./GeoIP.conf or ~/.config/maxmind/GeoIP.conf)")
	fs.StringVar(&repoURL, "blocklist-repo", defaultBlocklistRepo, "git URL of the blocklist repo (must match bitwire-it layout)")
	fs.StringVar(&cacheDir, "cache-dir", "", "cache parent dir, holds bitwire-it/ and maxmind/ subdirs (default: OS user cache)")
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
	if bind == "" {
		fs.Usage()
		os.Exit(1)
	}
	if cacheDir == "" {
		if d, err := os.UserCacheDir(); err == nil {
			cacheDir = d
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Blocklists: one git repo, two views sharing the same pull.
	repo := gitshallow.New(repoURL, filepath.Join(cacheDir, "bitwire-it"), 1, "")
	group := dataset.NewGroup(repo)
	inbound := dataset.Add(group, func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/inbound/single_ips.txt"),
			repo.FilePath("tables/inbound/networks.txt"),
		)
	})
	outbound := dataset.Add(group, func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/outbound/single_ips.txt"),
			repo.FilePath("tables/outbound/networks.txt"),
		)
	})
	if err := group.Load(ctx); err != nil {
		fatal("blocklists", err)
	}
	go group.Tick(ctx, refreshInterval, func(err error) {
		fmt.Fprintf(os.Stderr, "refresh: %v\n", err)
	})

	// GeoIP: downloaded via httpcache when GeoIP.conf is available.
	maxmindDir := filepath.Join(cacheDir, "maxmind")
	geo, err := geoip.OpenDatabases(
		confPath,
		filepath.Join(maxmindDir, geoip.CityEdition+".mmdb"),
		filepath.Join(maxmindDir, geoip.ASNEdition+".mmdb"),
	)
	if err != nil {
		fatal("geoip", err)
	}
	defer func() { _ = geo.Close() }()

	if err := serve(ctx, bind, inbound, outbound, geo); err != nil {
		fatal("serve", err)
	}
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "error: %s: %v\n", what, err)
	os.Exit(1)
}
