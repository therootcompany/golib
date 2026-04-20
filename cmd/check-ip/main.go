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
// --serve turns check-ip into a long-running HTTP server whose dataset.Tick
// loop actually gets exercised:
//
//	GET /         checks the request's client IP
//	GET /check    same, plus ?ip= overrides
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
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
	shutdownTimeout = 5 * time.Second
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	if cfg.Serve != "" {
		if fs.NArg() != 0 {
			fmt.Fprintln(os.Stderr, "error: --serve takes no positional args")
			os.Exit(1)
		}
		if err := serve(ctx, cfg); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(1)
	}
	blocked, err := oneshot(ctx, cfg, fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}
	if blocked {
		os.Exit(1)
	}
}

// Checker bundles the hot-swappable blocklist views with the static whitelist
// and geoip databases so one-shot and serve modes share the same report logic.
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
	geoPrint(w, r.Geo)
}

func geoPrint(w io.Writer, info geoip.Info) {
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

// newChecker builds a fully-populated Checker and starts background refresh.
// Returns a cleanup that closes the geoip databases.
func newChecker(ctx context.Context, cfg Config) (*Checker, func(), error) {
	group, inbound, outbound, err := newBlocklistGroup(cfg)
	if err != nil {
		return nil, nil, err
	}
	if err := group.Load(ctx); err != nil {
		return nil, nil, fmt.Errorf("blacklist: %w", err)
	}
	fmt.Fprintf(os.Stderr, "Loaded inbound=%d outbound=%d\n",
		inbound.Value().Size(), outbound.Value().Size())
	go group.Tick(ctx, refreshInterval)

	whitelist, err := loadWhitelist(cfg.Whitelist)
	if err != nil {
		return nil, nil, fmt.Errorf("whitelist: %w", err)
	}

	geo, err := geoip.OpenDatabases(cfg.GeoIPConf, cfg.CityDB, cfg.ASNDB)
	if err != nil {
		return nil, nil, fmt.Errorf("geoip: %w", err)
	}
	cleanup := func() { _ = geo.Close() }

	return &Checker{whitelist: whitelist, inbound: inbound, outbound: outbound, geo: geo}, cleanup, nil
}

func oneshot(ctx context.Context, cfg Config, ip string) (blocked bool, err error) {
	format, err := parseFormat(cfg.Format)
	if err != nil {
		return false, err
	}
	checker, cleanup, err := newChecker(ctx, cfg)
	if err != nil {
		return false, err
	}
	defer cleanup()
	return checker.Check(ip).Report(os.Stdout, format), nil
}

func serve(ctx context.Context, cfg Config) error {
	checker, cleanup, err := newChecker(ctx, cfg)
	if err != nil {
		return err
	}
	defer cleanup()

	handle := func(w http.ResponseWriter, r *http.Request, ip string) {
		format := requestFormat(r)
		if format == FormatJSON {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		checker.Check(ip).Report(w, format)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /check", func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ip == "" {
			ip = clientIP(r)
		}
		handle(w, r, ip)
	})
	mux.HandleFunc("GET /{$}", func(w http.ResponseWriter, r *http.Request) {
		handle(w, r, clientIP(r))
	})

	srv := &http.Server{
		Addr:    cfg.Serve,
		Handler: mux,
		BaseContext: func(_ net.Listener) context.Context {
			return ctx
		},
	}

	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()

	fmt.Fprintf(os.Stderr, "listening on %s\n", cfg.Serve)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// requestFormat picks a response format from ?format=, then Accept header.
func requestFormat(r *http.Request) Format {
	if q := r.URL.Query().Get("format"); q != "" {
		if f, err := parseFormat(q); err == nil {
			return f
		}
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return FormatJSON
	}
	return FormatPretty
}

// clientIP extracts the caller's IP, honoring X-Forwarded-For when present.
// The leftmost entry in X-Forwarded-For is the originating client; intermediate
// proxies append themselves rightward.
func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		first, _, _ := strings.Cut(xff, ",")
		return strings.TrimSpace(first)
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// newBlocklistGroup wires a dataset.Group to the configured source (local
// files, git, or HTTP-cached raw files) and registers inbound/outbound views.
func newBlocklistGroup(cfg Config) (
	_ *dataset.Group,
	inbound, outbound *dataset.View[ipcohort.Cohort],
	err error,
) {
	fetcher, inPaths, outPaths, err := newFetcher(cfg)
	if err != nil {
		return nil, nil, nil, err
	}
	g := dataset.NewGroup(fetcher)
	inbound = dataset.Add(g, loadCohort(inPaths))
	outbound = dataset.Add(g, loadCohort(outPaths))
	return g, inbound, outbound, nil
}

// newFetcher picks a Fetcher based on cfg and returns the on-disk file paths
// each view should parse after a sync.
func newFetcher(cfg Config) (fetcher dataset.Fetcher, inPaths, outPaths []string, err error) {
	switch {
	case cfg.Inbound != "" || cfg.Outbound != "":
		return dataset.NopFetcher{}, splitCSV(cfg.Inbound), splitCSV(cfg.Outbound), nil

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

func loadWhitelist(paths string) (*ipcohort.Cohort, error) {
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
