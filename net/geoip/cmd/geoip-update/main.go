package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"github.com/therootcompany/golib/net/geoip"
)

func main() {
	configPath := flag.String("config", "GeoIP.conf", "path to GeoIP.conf")
	dir := flag.String("dir", "", "directory to store .mmdb files (overrides DatabaseDirectory in config)")
	freshDays := flag.Int("fresh-days", 0, "skip download if file is younger than N days (default 3)")
	flag.Parse()

	cfg, err := geoip.ParseConf(*configPath)
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

	d := geoip.New(cfg.AccountID, cfg.LicenseKey)
	d.FreshDays = *freshDays

	exitCode := 0
	for _, edition := range cfg.EditionIDs {
		path := filepath.Join(outDir, edition+".mmdb")
		updated, err := d.Fetch(edition, path)
		if err != nil {
			fmt.Fprintf(os.Stderr, "error: %s: %v\n", edition, err)
			exitCode = 1
			continue
		}
		if updated {
			info, _ := os.Stat(path)
			fmt.Printf("updated: %s -> %s (%s)\n", edition, path, info.ModTime().Format("2006-01-02"))
		} else {
			info, _ := os.Stat(path)
			fmt.Printf("fresh:   %s (%s)\n", edition, info.ModTime().Format("2006-01-02"))
		}
	}
	os.Exit(exitCode)
}
