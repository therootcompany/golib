// geoip-update downloads GeoLite2 edition tarballs listed in GeoIP.conf
// via conditional HTTP GETs, writing them to the configured directory.
package main

import (
	"context"
	"encoding/base64"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/httpcache"
)

// Replaced by goreleaser / ldflags at build time.
var (
	name         = "geoip-update"
	version      = "0.0.0-dev"
	commit       = "0000000"
	date         = "0001-01-01"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal"
	licenseType  = "MPL-2.0"
)

func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

type Config struct {
	ConfPath string
	Dir      string
	BaseURL  string
	FreshDays int
}

func main() {
	cfg := Config{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.ConfPath, "config", "GeoIP.conf", "path to GeoIP.conf")
	fs.StringVar(&cfg.Dir, "dir", "", "directory to store .tar.gz files (overrides DatabaseDirectory in config)")
	fs.StringVar(&cfg.BaseURL, "base-url", "", "base URL for database downloads (overrides DownloadBase in geoip package)")
	fs.IntVar(&cfg.FreshDays, "fresh-days", 3, "skip download if file is younger than N days")

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

	data, err := os.ReadFile(cfg.ConfPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	conf, err := geoip.ParseConf(string(data))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	outDir := cfg.Dir
	if outDir == "" {
		outDir = conf.DatabaseDirectory
	}
	if outDir == "" {
		outDir = "."
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	if len(conf.EditionIDs) == 0 {
		fmt.Fprintf(os.Stderr, "error: no EditionIDs found in %s\n", cfg.ConfPath)
		os.Exit(1)
	}

	creds := base64.StdEncoding.EncodeToString([]byte(conf.AccountID + ":" + conf.LicenseKey))
	authHeader := http.Header{"Authorization": []string{"Basic " + creds}}
	maxAge := time.Duration(cfg.FreshDays) * 24 * time.Hour

	exitCode := 0
	for _, edition := range conf.EditionIDs {
		path := filepath.Join(outDir, geoip.TarGzName(edition))
		base := geoip.DownloadBase
		if cfg.BaseURL != "" {
			base = cfg.BaseURL
		}
		cacher := httpcache.New(
			base+"/"+edition+"/download?suffix=tar.gz",
			path,
		)
		cacher.MaxAge = maxAge
		cacher.Header = authHeader
		fmt.Fprintf(os.Stderr, "Fetching %s... ", edition)
		t := time.Now()
		updated, err := cacher.Fetch(context.Background())
		if err != nil {
			fmt.Fprintln(os.Stderr)
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", edition, err)
			exitCode = 1
			continue
		}
		state := "fresh"
		if updated {
			state = "updated"
		}
		fmt.Fprintf(os.Stderr, "%s (%s)\n", time.Since(t).Round(time.Millisecond), state)
		info, _ := os.Stat(path)
		fmt.Printf("%-10s %s -> %s (%s)\n", state+":", edition, path, info.ModTime().Format("2006-01-02"))
	}
	os.Exit(exitCode)
}
