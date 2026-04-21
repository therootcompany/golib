// geoip-update downloads GeoLite2 edition tarballs listed in GeoIP.conf
// via conditional HTTP GETs, writing them to the configured directory.
package main

import (
	"errors"
	"flag"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/httpcache"
)

const version = "dev"

type Config struct {
	ConfPath  string
	Dir       string
	FreshDays int
}

func main() {
	cfg := Config{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.ConfPath, "config", "GeoIP.conf", "path to GeoIP.conf")
	fs.StringVar(&cfg.Dir, "dir", "", "directory to store .tar.gz files (overrides DatabaseDirectory in config)")
	fs.IntVar(&cfg.FreshDays, "fresh-days", 3, "skip download if file is younger than N days")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags]\n", os.Args[0])
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			fmt.Fprintf(os.Stdout, "geoip-update %s\n", version)
			os.Exit(0)
		case "help", "-help", "--help":
			fmt.Fprintf(os.Stdout, "geoip-update %s\n\n", version)
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

	authHeader := http.Header{"Authorization": []string{httpcache.BasicAuth(conf.AccountID, conf.LicenseKey)}}
	maxAge := time.Duration(cfg.FreshDays) * 24 * time.Hour

	exitCode := 0
	for _, edition := range conf.EditionIDs {
		path := filepath.Join(outDir, geoip.TarGzName(edition))
		cacher := &httpcache.Cacher{
			URL:    geoip.DownloadBase + "/" + edition + "/download?suffix=tar.gz",
			Path:   path,
			MaxAge: maxAge,
			Header: authHeader,
		}
		fmt.Fprintf(os.Stderr, "Fetching %s... ", edition)
		t := time.Now()
		updated, err := cacher.Fetch()
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
