// geoip-update downloads GeoLite2 edition tarballs listed in GeoIP.conf
// via conditional HTTP GETs, writing them to the configured directory.
package main

import (
	"context"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime/debug"
	"strings"
	"syscall"
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
	v, c, d := version, commit, date
	if c == "0000000" {
		if bi, ok := debug.ReadBuildInfo(); ok {
			for _, setting := range bi.Settings {
				switch setting.Key {
				case "vcs.revision":
					c = setting.Value
				case "vcs.time":
					d = setting.Value
				case "vcs.modified":
					if setting.Value == "true" {
						d += "+dirty"
					}
				}
			}
		}
	}
	if len(c) > 7 {
		c = c[:7]
	}
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, v, c, d)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

const defaultFailureBackoff = 6 * time.Hour

type Config struct {
	ConfPath      string
	Dir           string
	BaseURL       string
	FreshDays     int
	Format        string
	HumanReadable bool
}

type result struct {
	State   string `json:"state"`
	Edition string `json:"edition"`
	Path    string `json:"path"`
	Date    string `json:"date,omitempty"`
	Error   string `json:"error,omitempty"`
}

func main() {
	cfg := Config{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.ConfPath, "config", "GeoIP.conf", "path to GeoIP.conf")
	fs.StringVar(&cfg.Dir, "dir", "", "directory to store .tar.gz files (overrides DatabaseDirectory in config)")
	fs.StringVar(&cfg.BaseURL, "base-url", "", "base URL for database downloads (overrides DownloadBase in geoip package)")
	fs.IntVar(&cfg.FreshDays, "fresh-days", 3, "skip download if file is younger than N days")
	fs.StringVar(&cfg.Format, "format", "", "output format: pretty, tsv, csv, json (default: auto)")
	fs.BoolVar(&cfg.HumanReadable, "human-readable", false, "use human-readable output (same as --format pretty)")
	fs.BoolVar(&cfg.HumanReadable, "h", false, "use human-readable output (same as --format pretty)")
	fs.Usage = func() {
		w := fs.Output()
		_, _ = fmt.Fprintf(w, "USAGE\n  %s [flags]\n\nFLAGS\n", name)
		fs.PrintDefaults()
		_, _ = fmt.Fprintln(w, "\nCONFIGURATION\n  GeoIP.conf uses AccountID, LicenseKey, EditionIDs, and DatabaseDirectory.")
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
		os.Exit(2)
	}
	if fs.NArg() != 0 {
		_, _ = fmt.Fprintf(os.Stderr, "error: unexpected arguments: %s\n", strings.Join(fs.Args(), " "))
		os.Exit(2)
	}
	if cfg.FreshDays < 0 {
		_, _ = fmt.Fprintln(os.Stderr, "error: -fresh-days must not be negative")
		os.Exit(2)
	}
	if cfg.HumanReadable {
		if cfg.Format != "" && cfg.Format != "pretty" {
			_, _ = fmt.Fprintln(os.Stderr, "error: -h conflicts with a non-pretty -format")
			os.Exit(2)
		}
		cfg.Format = "pretty"
	}
	format, err := resolveFormat(cfg.Format, os.Stdout)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(2)
	}

	data, err := os.ReadFile(cfg.ConfPath)
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	conf, err := geoip.ParseConf(string(data))
	if err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: %v\n", err)
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
		_, _ = fmt.Fprintf(os.Stderr, "error: mkdir %s: %v\n", outDir, err)
		os.Exit(1)
	}

	if len(conf.EditionIDs) == 0 {
		_, _ = fmt.Fprintf(os.Stderr, "error: no EditionIDs found in %s\n", cfg.ConfPath)
		os.Exit(1)
	}

	creds := base64.StdEncoding.EncodeToString([]byte(conf.AccountID + ":" + conf.LicenseKey))
	authHeader := http.Header{"Authorization": []string{"Basic " + creds}}
	maxAge := time.Duration(cfg.FreshDays) * 24 * time.Hour
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	results := make([]result, 0, len(conf.EditionIDs))
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
		cacher.FailureBackoff = defaultFailureBackoff
		cacher.Header = authHeader
		_, _ = fmt.Fprintf(os.Stderr, "Fetching %s... ", edition)
		t := time.Now()
		updated, err := cacher.Fetch(ctx)
		if err != nil {
			_, _ = fmt.Fprintln(os.Stderr)
			_, _ = fmt.Fprintf(os.Stderr, "error: %s: %v\n", edition, err)
			results = append(results, result{State: "error", Edition: edition, Path: path, Error: err.Error()})
			exitCode = 1
			continue
		}
		state := "fresh"
		if updated {
			state = "updated"
		}
		_, _ = fmt.Fprintf(os.Stderr, "%s (%s)\n", time.Since(t).Round(time.Millisecond), state)
		info, statErr := os.Stat(path)
		date := ""
		if statErr == nil {
			date = info.ModTime().Format("2006-01-02")
		}
		results = append(results, result{State: state, Edition: edition, Path: path, Date: date})
	}
	if err := writeResults(os.Stdout, format, results); err != nil {
		_, _ = fmt.Fprintf(os.Stderr, "error: write output: %v\n", err)
		exitCode = 1
	}
	os.Exit(exitCode)
}

func resolveFormat(format string, out *os.File) (string, error) {
	if format != "" {
		return parseFormat(format)
	}
	if isTTYish(out) {
		return "pretty", nil
	}
	return "tsv", nil
}

func parseFormat(format string) (string, error) {
	switch format {
	case "pretty", "tsv", "csv", "json":
		return format, nil
	default:
		return "", fmt.Errorf("invalid format %q: want pretty, tsv, csv, or json", format)
	}
}

func isTTYish(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	m := os.ModeDevice | os.ModeCharDevice
	return fi.Mode()&m == m
}

func writeResults(w io.Writer, format string, results []result) error {
	switch format {
	case "json":
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	case "csv", "tsv":
		cw := csv.NewWriter(w)
		if format == "tsv" {
			cw.Comma = '\t'
		} else if err := cw.Write([]string{"state", "edition", "path", "date", "error"}); err != nil {
			return err
		}
		for _, r := range results {
			if err := cw.Write([]string{r.State, r.Edition, r.Path, r.Date, r.Error}); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	default:
		for _, r := range results {
			if r.State == "error" {
				if _, err := fmt.Fprintf(w, "%-10s %s -> %s (%s)\n", r.State+":", r.Edition, r.Path, r.Error); err != nil {
					return err
				}
				continue
			}
			if _, err := fmt.Fprintf(w, "%-10s %s -> %s (%s)\n", r.State+":", r.Edition, r.Path, r.Date); err != nil {
				return err
			}
		}
		return nil
	}
}
