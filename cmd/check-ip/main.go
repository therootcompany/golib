// check-ip runs an HTTP API that reports whether an IP appears in the
// configured blocklist repo and enriches the response with MaxMind
// GeoLite2 City + ASN data.
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
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/net/iplist"
	"github.com/therootcompany/golib/sync/dataset"
)

// Replaced by goreleaser / ldflags at build time.
var (
	name         = "check-ip"
	version      = "0.0.0-dev"
	commit       = "0000000"
	date         = "0001-01-01"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal"
	licenseType  = "MPL-2.0"
)

const (
	defaultBlocklistRepo = "https://github.com/bitwire-it/ipblocklist.git"
	refreshInterval      = 47 * time.Minute
)

// printVersion writes version, copyright, and license info to w.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

// isTTYish reports whether f is a terminal device.
func isTTYish(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	m := os.ModeDevice | os.ModeCharDevice
	return fi.Mode()&m == m
}

// parseFormat validates and returns the output format.
func parseFormat(s string) (string, error) {
	switch s {
	case "", "pretty", "tsv", "csv", "json":
		return s, nil
	default:
		return "", fmt.Errorf("invalid format %q: want pretty, tsv, csv, json", s)
	}
}

// commafy formats n with comma thousands separators (e.g. 3406727 -> "3,406,727").
func commafy(n int) string {
	s := strconv.Itoa(n)
	neg := ""
	if n < 0 {
		neg, s = "-", s[1:]
	}
	if len(s) <= 3 {
		return neg + s
	}
	var b strings.Builder
	head := len(s) % 3
	if head > 0 {
		b.WriteString(s[:head])
		b.WriteByte(',')
	}
	for i := head; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return neg + b.String()
}

// IPCheck holds the parsed CLI config and the loaded data sources used by
// the HTTP handler.
type IPCheck struct {
	Bind          string
	GeoIPConfPath string
	GeoIPURL      string
	RepoURL       string
	CacheDir      string
	WhitelistPath string
	AsyncLoad     bool
	Format        string

	// GeoIPBasicAuth is the pre-encoded Authorization header value for
	// MaxMind downloads.
	GeoIPBasicAuth string

	inbound   *dataset.View[ipcohort.Cohort]
	outbound  *dataset.View[ipcohort.Cohort]
	whitelist atomic.Pointer[ipcohort.Cohort]
	geo       *dataset.View[geoip.Databases]
}

func main() {
	cfg := IPCheck{}
	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.Bind, "serve", "", "bind address for the HTTP API, e.g. :8080")
	fs.StringVar(&cfg.GeoIPConfPath, "geoip-conf", "", "path to GeoIP.conf (default: ./GeoIP.conf or ~/.config/maxmind/GeoIP.conf)")
	fs.StringVar(&cfg.RepoURL, "blocklist-repo", defaultBlocklistRepo, "git URL of the blocklist repo (must match bitwire-it layout)")
	fs.StringVar(&cfg.CacheDir, "cache-dir", "", "cache parent dir, holds bitwire-it/ and maxmind/ subdirs (default: ~/.cache)")
	fs.StringVar(&cfg.GeoIPURL, "geoip-url", "", "GeoIP download URL (overrides geoip.DownloadBase)")
	fs.StringVar(&cfg.WhitelistPath, "whitelist", "", "path to a file of IPs and/or CIDRs (one per line) that override block decisions")
	fs.BoolVar(&cfg.AsyncLoad, "async-load", false, "with --serve: start the HTTP server immediately and populate blocklists+whitelist in the background (/healthz returns 503 until ready). Ignored in CLI mode.")
	fs.StringVar(&cfg.Format, "format", "", "output format: pretty, tsv, csv, json (default: auto)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <ip> [ip...]\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s --serve <bind> [flags]\n", os.Args[0])
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			printVersion(os.Stdout)
			os.Exit(0)
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			fmt.Fprintln(os.Stdout)
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
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("cache-dir: %v", err)
		}
		cfg.CacheDir = filepath.Join(home, ".cache")
	}
	format, err := parseFormat(cfg.Format)
	if err != nil {
		log.Fatalf("format: %v", err)
	}
	cfg.Format = format

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
		cfg.GeoIPBasicAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(conf.AccountID+":"+conf.LicenseKey))
	}
	// Allow overriding the license key via env var.
	if envKey := os.Getenv("MAXMIND_LICENSE_KEY"); envKey != "" {
		if cfg.GeoIPConfPath == "" {
			log.Fatalf("MAXMIND_LICENSE_KEY requires --geoip-conf for AccountID")
		}
		cfg.GeoIPBasicAuth = "Basic " + base64.StdEncoding.EncodeToString([]byte(cfg.GeoIPBasicAuth[6:]+":"+envKey))
	}

	// Blocklists: git repo with inbound + outbound IP cohort files.
	repo := gitshallow.New(cfg.RepoURL, filepath.Join(cfg.CacheDir, "bitwire-it"), 1, "")
	repo.MaxAge = refreshInterval
	blocklists := dataset.NewSet(repo)
	asyncServe := cfg.AsyncLoad && cfg.Bind != ""
	addCohort := func(s *dataset.Set, loader func(context.Context) (*ipcohort.Cohort, error)) *dataset.View[ipcohort.Cohort] {
		if asyncServe {
			return dataset.AddInitial(s, &ipcohort.Cohort{}, loader)
		}
		return dataset.Add(s, loader)
	}
	cfg.inbound = addCohort(blocklists, func(_ context.Context) (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/inbound/single_ips.txt"),
			repo.FilePath("tables/inbound/networks.txt"),
		)
	})
	cfg.outbound = addCohort(blocklists, func(_ context.Context) (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/outbound/single_ips.txt"),
			repo.FilePath("tables/outbound/networks.txt"),
		)
	})
	loadBlocklists := func() {
		fmt.Fprint(os.Stderr, "Loading blocklists... ")
		t := time.Now()
		if err := blocklists.Load(context.Background()); err != nil {
			fmt.Fprintln(os.Stderr)
			log.Printf("blocklists: %v", err)
			if !asyncServe {
				os.Exit(1)
			}
			return
		}
		fmt.Fprintf(os.Stderr, "%s (inbound=%s, outbound=%s)\n",
			time.Since(t).Round(time.Millisecond),
			commafy(cfg.inbound.Value().Size()),
			commafy(cfg.outbound.Value().Size()),
		)
	}
	if !asyncServe {
		loadBlocklists()
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
	downloadBase := geoip.DownloadBase
	if cfg.GeoIPURL != "" {
		downloadBase = strings.TrimRight(cfg.GeoIPURL, "/")
	}
	cityCacher := httpcache.New(
		downloadBase+"/GeoLite2-City/download?suffix=tar.gz",
		filepath.Join(maxmindDir, geoip.TarGzName(geoip.CityEdition)))
	cityCacher.Header = authHeader
	cityCacher.MaxAge = 3 * 24 * time.Hour
	asnCacher := httpcache.New(
		downloadBase+"/GeoLite2-ASN/download?suffix=tar.gz",
		filepath.Join(maxmindDir, geoip.TarGzName(geoip.ASNEdition)))
	asnCacher.Header = authHeader
	asnCacher.MaxAge = 3 * 24 * time.Hour
	geoSet := dataset.NewSet(cityCacher, asnCacher)
	cfg.geo = dataset.Add(geoSet, func(_ context.Context) (*geoip.Databases, error) {
		return geoip.Open(maxmindDir)
	})
	fmt.Fprint(os.Stderr, "Loading geoip... ")
	tGeo := time.Now()
	if err := geoSet.Load(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr)
		log.Fatalf("geoip: %v", err)
	}
	fmt.Fprintf(os.Stderr, "%s\n", time.Since(tGeo).Round(time.Millisecond))
	defer func() { _ = cfg.geo.Value().Close() }()

	// Whitelist: combined IPs + CIDRs in one file, refreshed on an interval.
	// A match here overrides any block decision from the blocklists.
	// Uses net/iplist.Source — the refreshed-IP-list primitive net/ippolicy
	// builds on — instead of a dataset wrapper; iplist owns the refresh.
	if cfg.WhitelistPath != "" {
		t := time.Now()
		whitelistSrc, err := iplist.NewSource(context.Background(), iplist.SourceConfig{
			Source:          cfg.WhitelistPath,
			RefreshInterval: refreshInterval,
			Optional:        true,
		})
		if err != nil {
			log.Fatalf("whitelist: %v", err)
		}
		store := func() {
			coh, perr := ipcohort.Parse(whitelistSrc.Entries())
			if perr != nil {
				log.Printf("whitelist: %v", perr)
			}
			cfg.whitelist.Store(coh)
		}
		store()
		whitelistSrc.Subscribe(func(e iplist.SourceEvent) {
			if e.Err != nil {
				log.Printf("whitelist refresh: %v", e.Err)
				return
			}
			store()
		})
		fmt.Fprintf(os.Stderr, "Loading whitelist... %s (entries=%s)\n",
			time.Since(t).Round(time.Millisecond),
			commafy(cfg.whitelist.Load().Size()),
		)
	}

	// Blank line separates the stderr "Loading ..." block from the real
	// output (stdout results for CLI mode, or the stderr "listening on"
	// log for serve mode).
	fmt.Fprintln(os.Stderr)

	// Auto-detect format: pretty on TTY, tsv when piped.
	if cfg.Format == "" {
		if isTTYish(os.Stdout) {
			cfg.Format = "pretty"
		} else {
			cfg.Format = "tsv"
		}
	}

	for _, ip := range ips {
		res := cfg.lookup(ip)
		switch cfg.Format {
		case "json":
			enc := json.NewEncoder(os.Stdout)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
		case "csv":
			w := csv.NewWriter(os.Stdout)
			w.Write([]string{"ip", "blocked", "blocked_inbound", "blocked_outbound", "allowlisted", "city", "region", "country", "country_iso", "asn", "asn_org"})
			w.Write([]string{res.IP, strconv.FormatBool(res.Blocked), strconv.FormatBool(res.BlockedInbound), strconv.FormatBool(res.BlockedOutbound), strconv.FormatBool(res.Allowlisted), res.Geo.City, res.Geo.Region, res.Geo.Country, res.Geo.CountryISO, strconv.Itoa(int(res.Geo.ASN)), res.Geo.ASNOrg})
			w.Flush()
		case "tsv":
			fmt.Fprintf(os.Stdout, "%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
				res.IP,
				strconv.FormatBool(res.Blocked),
				strconv.FormatBool(res.BlockedInbound),
				strconv.FormatBool(res.BlockedOutbound),
				strconv.FormatBool(res.Allowlisted),
				res.Geo.City,
				res.Geo.Region,
				res.Geo.Country,
				res.Geo.CountryISO,
				strconv.Itoa(int(res.Geo.ASN)),
				res.Geo.ASNOrg,
			)
		default:
			cfg.writePretty(os.Stdout, res)
		}
	}
	if cfg.Bind == "" {
		return
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if asyncServe {
		go loadBlocklists()
	}
	go blocklists.Tick(ctx, refreshInterval, func(err error) {
		log.Printf("blocklists refresh: %v", err)
	})
	go geoSet.Tick(ctx, refreshInterval, func(err error) {
		log.Printf("geoip refresh: %v", err)
	})
	if err := cfg.serve(ctx); err != nil {
		log.Fatalf("serve: %v", err)
	}
}
