// check-ip reports whether an IPv4 address appears in the bitwire-it
// inbound/outbound blocklists and, when configured, prints GeoIP info.
//
// Source selection (in order of precedence):
//
//   - --inbound / --outbound   use local files (no syncing)
//   - --git URL                shallow-clone a git repo of blocklists
//   - (default)                fetch raw blocklist files over HTTP with caching
//
// Each mode builds a sync/dataset.Group: one Fetcher shared by the inbound
// and outbound views, so a single git pull (or HTTP-304 cycle) drives both.
//
// --serve turns check-ip into a long-running HTTP server; see server.go.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/dataset"
)

const (
	bitwireGitURL  = "https://github.com/bitwire-it/ipblocklist.git"
	bitwireRawBase = "https://github.com/bitwire-it/ipblocklist/raw/refs/heads/main/tables"

	refreshInterval = 47 * time.Minute
)

type Config struct {
	DataDir   string
	GitURL    string
	Whitelist string
	Inbound   string
	Outbound  string
	GeoIPConf string
	CityDB    string
	ASNDB     string
	Serve     string
	Format    string
}

func main() {
	cfg := Config{}

	fs := flag.NewFlagSet(os.Args[0], flag.ContinueOnError)
	fs.StringVar(&cfg.DataDir, "data-dir", "", "blacklist cache dir (default ~/.cache/bitwire-it)")
	fs.StringVar(&cfg.GitURL, "git", "", "git URL to clone/pull blacklist from (e.g. "+bitwireGitURL+")")
	fs.StringVar(&cfg.Whitelist, "whitelist", "", "comma-separated paths to whitelist files")
	fs.StringVar(&cfg.Inbound, "inbound", "", "comma-separated paths to inbound blacklist files")
	fs.StringVar(&cfg.Outbound, "outbound", "", "comma-separated paths to outbound blacklist files")
	fs.StringVar(&cfg.GeoIPConf, "geoip-conf", "", "path to GeoIP.conf (auto-discovered if absent)")
	fs.StringVar(&cfg.CityDB, "city-db", "", "path to GeoLite2-City.mmdb (skips auto-download)")
	fs.StringVar(&cfg.ASNDB, "asn-db", "", "path to GeoLite2-ASN.mmdb (skips auto-download)")
	fs.StringVar(&cfg.Serve, "serve", "", "start HTTP server at addr:port (e.g. :8080) instead of one-shot check")
	fs.StringVar(&cfg.Format, "format", "", "output format: pretty, json (default pretty)")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [flags] <ip-address>\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "       %s --serve :8080 [flags]\n", os.Args[0])
		fs.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "-version", "--version", "version":
			fmt.Fprintln(os.Stdout, "check-ip")
			os.Exit(0)
		case "help", "-help", "--help":
			fmt.Fprintln(os.Stdout, "check-ip")
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
	format, err := parseFormat(cfg.Format)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Open the three "databases" that feed every IP check:
	//
	//   1. blocklists — inbound + outbound cohorts, hot-swapped on refresh
	//   2. whitelist  — static cohort loaded once from disk
	//   3. geoip      — city + ASN mmdb readers (optional)
	//
	// The blocklist Group.Tick goroutine refreshes in the background so the
	// serve path actually exercises dataset's hot-swap.

	group, inbound, outbound, err := openBlocklists(cfg)
	if err != nil {
		fatal("blocklists", err)
	}
	if err := group.Load(ctx); err != nil {
		fatal("blocklists", err)
	}
	fmt.Fprintf(os.Stderr, "loaded inbound=%d outbound=%d\n",
		inbound.Value().Size(), outbound.Value().Size())
	go group.Tick(ctx, refreshInterval, func(err error) {
		fmt.Fprintf(os.Stderr, "refresh: %v\n", err)
	})

	whitelist, err := openWhitelist(cfg.Whitelist)
	if err != nil {
		fatal("whitelist", err)
	}

	geo, err := geoip.OpenDatabases(cfg.GeoIPConf, cfg.CityDB, cfg.ASNDB)
	if err != nil {
		fatal("geoip", err)
	}
	defer func() { _ = geo.Close() }()

	checker := &Checker{
		whitelist: whitelist,
		inbound:   inbound,
		outbound:  outbound,
		geo:       geo,
	}

	if cfg.Serve != "" {
		if fs.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "error: --serve takes no positional args")
			os.Exit(1)
		}
		if err := serve(ctx, cfg, checker); err != nil {
			fatal("serve", err)
		}
		return
	}

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	blocked := checker.Check(fs.Arg(0)).Report(os.Stdout, format)
	if blocked {
		os.Exit(1)
	}
}

func fatal(what string, err error) {
	fmt.Fprintf(os.Stderr, "error: %s: %v\n", what, err)
	os.Exit(1)
}

// Checker bundles the three databases plus the lookup + render logic.
type Checker struct {
	whitelist *ipcohort.Cohort
	inbound   *dataset.View[ipcohort.Cohort]
	outbound  *dataset.View[ipcohort.Cohort]
	geo       *geoip.Databases
}

// Result is the structured verdict for a single IP.
type Result struct {
	IP              string     `json:"ip"`
	Blocked         bool       `json:"blocked"`
	BlockedInbound  bool       `json:"blocked_inbound"`
	BlockedOutbound bool       `json:"blocked_outbound"`
	Whitelisted     bool       `json:"whitelisted,omitempty"`
	Geo             geoip.Info `json:"geo,omitzero"`
}

// Check returns the structured verdict for ip without rendering.
func (c *Checker) Check(ip string) Result {
	whitelisted := c.whitelist != nil && c.whitelist.Contains(ip)
	in := !whitelisted && cohortContains(c.inbound.Value(), ip)
	out := !whitelisted && cohortContains(c.outbound.Value(), ip)
	return Result{
		IP:              ip,
		Blocked:         in || out,
		BlockedInbound:  in,
		BlockedOutbound: out,
		Whitelisted:     whitelisted,
		Geo:             c.geo.Lookup(ip),
	}
}

// Format selects the report rendering.
type Format string

const (
	FormatPretty Format = "pretty"
	FormatJSON   Format = "json"
)

func parseFormat(s string) (Format, error) {
	switch s {
	case "", "pretty":
		return FormatPretty, nil
	case "json":
		return FormatJSON, nil
	default:
		return "", fmt.Errorf("invalid --format %q (want: pretty, json)", s)
	}
}

// Report renders r to w in the given format. Returns r.Blocked for convenience.
func (r Result) Report(w io.Writer, format Format) bool {
	switch format {
	case FormatJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
	default:
		r.writePretty(w)
	}
	return r.Blocked
}

func (r Result) writePretty(w io.Writer) {
	switch {
	case r.BlockedInbound && r.BlockedOutbound:
		fmt.Fprintf(w, "%s is BLOCKED (inbound + outbound)\n", r.IP)
	case r.BlockedInbound:
		fmt.Fprintf(w, "%s is BLOCKED (inbound)\n", r.IP)
	case r.BlockedOutbound:
		fmt.Fprintf(w, "%s is BLOCKED (outbound)\n", r.IP)
	default:
		fmt.Fprintf(w, "%s is allowed\n", r.IP)
	}
	writeGeo(w, r.Geo)
}

func writeGeo(w io.Writer, info geoip.Info) {
	var parts []string
	if info.City != "" {
		parts = append(parts, info.City)
	}
	if info.Region != "" {
		parts = append(parts, info.Region)
	}
	if info.Country != "" {
		parts = append(parts, fmt.Sprintf("%s (%s)", info.Country, info.CountryISO))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "  Location: %s\n", strings.Join(parts, ", "))
	}
	if info.ASN != 0 {
		fmt.Fprintf(w, "  ASN:      AS%d %s\n", info.ASN, info.ASNOrg)
	}
}

func cohortContains(c *ipcohort.Cohort, ip string) bool {
	return c != nil && c.Contains(ip)
}

// openBlocklists picks a Fetcher based on cfg and wires inbound/outbound views
// into a shared dataset.Group so one pull drives both.
func openBlocklists(cfg Config) (
	_ *dataset.Group,
	inbound, outbound *dataset.View[ipcohort.Cohort],
	err error,
) {
	fetcher, inPaths, outPaths, err := newBlocklistFetcher(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	g := dataset.NewGroup(fetcher)
	inbound = dataset.Add(g, loadCohort(inPaths))
	outbound = dataset.Add(g, loadCohort(outPaths))
	return g, inbound, outbound, nil
}

// newBlocklistFetcher returns a dataset.Fetcher and the on-disk paths each
// view should parse after a sync.
func newBlocklistFetcher(cfg Config) (fetcher dataset.Fetcher, inPaths, outPaths []string, err error) {
	switch {
	case cfg.Inbound != "" || cfg.Outbound != "":
		inPaths := splitCSV(cfg.Inbound)
		outPaths := splitCSV(cfg.Outbound)
		all := append(append([]string(nil), inPaths...), outPaths...)
		return dataset.PollFiles(all...), inPaths, outPaths, nil

	case cfg.GitURL != "":
		dir, err := cacheDir(cfg.DataDir)
		if err != nil {
			return nil, nil, nil, err
		}
		repo := gitshallow.New(cfg.GitURL, dir, 1, "")
		return repo,
			[]string{
				repo.FilePath("tables/inbound/single_ips.txt"),
				repo.FilePath("tables/inbound/networks.txt"),
			},
			[]string{
				repo.FilePath("tables/outbound/single_ips.txt"),
				repo.FilePath("tables/outbound/networks.txt"),
			},
			nil

	default:
		dir, err := cacheDir(cfg.DataDir)
		if err != nil {
			return nil, nil, nil, err
		}
		cachers := []*httpcache.Cacher{
			httpcache.New(bitwireRawBase+"/inbound/single_ips.txt", filepath.Join(dir, "inbound_single_ips.txt")),
			httpcache.New(bitwireRawBase+"/inbound/networks.txt", filepath.Join(dir, "inbound_networks.txt")),
			httpcache.New(bitwireRawBase+"/outbound/single_ips.txt", filepath.Join(dir, "outbound_single_ips.txt")),
			httpcache.New(bitwireRawBase+"/outbound/networks.txt", filepath.Join(dir, "outbound_networks.txt")),
		}
		return dataset.FetcherFunc(func() (bool, error) {
				var any bool
				for _, c := range cachers {
					u, err := c.Fetch()
					if err != nil {
						return false, err
					}
					any = any || u
				}
				return any, nil
			}),
			[]string{cachers[0].Path, cachers[1].Path},
			[]string{cachers[2].Path, cachers[3].Path},
			nil
	}
}

func loadCohort(paths []string) func() (*ipcohort.Cohort, error) {
	return func() (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(paths...)
	}
}

func openWhitelist(paths string) (*ipcohort.Cohort, error) {
	if paths == "" {
		return nil, nil
	}
	return ipcohort.LoadFiles(strings.Split(paths, ",")...)
}

func cacheDir(override string) (string, error) {
	dir := override
	if dir == "" {
		base, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dir = filepath.Join(base, "bitwire-it")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	return dir, nil
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(s, ",")
}
