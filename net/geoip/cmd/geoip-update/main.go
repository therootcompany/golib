package main

import (
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/httpcache"
)

func main() {
	configPath := flag.String("config", "GeoIP.conf", "path to GeoIP.conf")
	dir := flag.String("dir", "", "directory to store .tar.gz files (overrides DatabaseDirectory in config)")
	freshDays := flag.Int("fresh-days", 3, "skip download if file is younger than N days")
	flag.Parse()

	data, err := os.ReadFile(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	cfg, err := geoip.ParseConf(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	outDir := *dir
	if outDir == "" {
		outDir = cfg.DatabaseDirectory
	}
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	if len(cfg.EditionIDs) == 0 {
		fmt.Fprintf(os.Stderr, "error: no EditionIDs found in %s\n", *configPath)
		os.Exit(1)
	}

	authHeader := http.Header{"Authorization": []string{httpcache.BasicAuth(cfg.AccountID, cfg.LicenseKey)}}
	maxAge := time.Duration(*freshDays) * 24 * time.Hour

	exitCode := 0
	for _, edition := range cfg.EditionIDs {
		path := filepath.Join(outDir, geoip.TarGzName(edition))
		cacher := &httpcache.Cacher{
			URL:    geoip.DownloadBase + "/" + edition + "/download?suffix=tar.gz",
			Path:   path,
			MaxAge: maxAge,
			Header: authHeader,
		}
		updated, err := cacher.Fetch()
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", edition, err)
			exitCode = 1
			continue
		}
		info, _ := os.Stat(path)
		state := "fresh:  "
		if updated {
			state = "updated:"
		}
		fmt.Printf("%s %s -> %s (%s)\n", state, edition, path, info.ModTime().Format("2006-01-02"))
	}
	os.Exit(exitCode)
}
