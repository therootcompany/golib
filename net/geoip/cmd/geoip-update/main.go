package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/therootcompany/golib/net/geoip"
)

func main() {
	configPath := flag.String("config", "GeoIP.conf", "path to GeoIP.conf")
	dir := flag.String("dir", "", "directory to store .mmdb files (overrides DatabaseDirectory in config)")
	freshDays := flag.Int("fresh-days", 0, "skip download if file is younger than N days (default 3)")
	flag.Parse()

	cfg, err := parseConf(*configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	outDir := *dir
	if outDir == "" {
		outDir = cfg["DatabaseDirectory"]
	}
	if outDir == "" {
		outDir = "."
	}

	if err := os.MkdirAll(outDir, 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "error: mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	accountID := cfg["AccountID"]
	licenseKey := cfg["LicenseKey"]
	if accountID == "" || licenseKey == "" {
		fmt.Fprintf(os.Stderr, "error: AccountID and LicenseKey are required in %s\n", *configPath)
		os.Exit(1)
	}

	editions := strings.Fields(cfg["EditionIDs"])
	if len(editions) == 0 {
		fmt.Fprintf(os.Stderr, "error: no EditionIDs found in %s\n", *configPath)
		os.Exit(1)
	}

	d := geoip.New(accountID, licenseKey)
	d.FreshDays = *freshDays

	exitCode := 0
	for _, edition := range editions {
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

// parseConf reads a geoipupdate-style config file (key value pairs, # comments).
func parseConf(path string) (map[string]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	cfg := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		cfg[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	return cfg, scanner.Err()
}
