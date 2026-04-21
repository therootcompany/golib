package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/netip"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/term"

	"github.com/joho/godotenv"

	"github.com/therootcompany/golib/net/formmailer"
	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/gitshallow"
	"github.com/therootcompany/golib/net/httpcache"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/dataset"
)

const (
	name         = "form2email"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal"
	licenseType  = "CC0-1.0"

	defaultBlocklistRepo = "https://github.com/bitwire-it/ipblocklist.git"
	refreshInterval      = 47 * time.Minute

	requestsPerMinute = 5
	burstSize         = 3
)

var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01T00:00:00Z"
)

func printVersion(out io.Writer) {
	if len(commit) > 7 {
		commit = commit[:7]
	}
	_, _ = fmt.Fprintf(out, "%s v%s %s (%s)\n", name, version, commit, date)
	_, _ = fmt.Fprintf(out, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(out, "Licensed under the %s license\n", licenseType)
}

type MainConfig struct {
	showVersion   bool
	listenAddr    string
	smtpHost      string
	smtpFrom      string
	smtpToList    string
	smtpUser      string
	smtpPass      string
	smtpSubject   string
	successFile   string
	errorFile     string
	responseType  string
	blocklistRepo string
	cacheDir      string
	geoipConfPath string
}

func main() {
	home, _ := os.UserHomeDir()
	_ = godotenv.Load()
	_ = godotenv.Load(filepath.Join(home, ".config/form2mail/env"))

	cfg := MainConfig{
		listenAddr:    "localhost:3081",
		smtpHost:      os.Getenv("SMTP_HOST"),
		smtpFrom:      os.Getenv("SMTP_FROM"),
		smtpToList:    os.Getenv("SMTP_TO"),
		smtpUser:      os.Getenv("SMTP_USER"),
		smtpSubject:   "Website contact request from {.Email}",
		successFile:   "success-file.html",
		errorFile:     "error-file.html",
		responseType:  "text/plain",
		blocklistRepo: defaultBlocklistRepo,
	}

	fs := flag.NewFlagSet("", flag.ContinueOnError)
	fs.BoolVar(&cfg.showVersion, "version", false, "Print version and exit")
	fs.StringVar(&cfg.listenAddr, "listen", cfg.listenAddr, "Address to listen on")
	fs.StringVar(&cfg.smtpHost, "smtp-host", cfg.smtpHost, "SMTP server:port e.g. smtp.gmail.com:587 (required)")
	fs.StringVar(&cfg.smtpFrom, "smtp-from", cfg.smtpFrom, "Sender email e.g. you@gmail.com (required)")
	fs.StringVar(&cfg.smtpToList, "smtp-to", cfg.smtpToList, "Recipient email e.g. alerts@yourdomain.com (required)")
	fs.StringVar(&cfg.smtpUser, "smtp-user", cfg.smtpUser, "SMTP username (defaults to smtp-from if not set)")
	fs.StringVar(&cfg.successFile, "success-file", cfg.successFile, "HTML or JSON file to reply with on success.")
	fs.StringVar(&cfg.errorFile, "error-file", cfg.errorFile, "HTML or JSON file to reply with on failure.")
	fs.StringVar(&cfg.blocklistRepo, "blocklist-repo", cfg.blocklistRepo, "git URL of the bitwire-it-compatible blocklist repo")
	fs.StringVar(&cfg.cacheDir, "cache-dir", "", "cache parent dir (default: ~/.cache)")
	fs.StringVar(&cfg.geoipConfPath, "geoip-conf", "", "path to GeoIP.conf (default: ./GeoIP.conf or ~/.config/maxmind/GeoIP.conf)")

	fs.Usage = func() {
		printVersion(os.Stderr)
		fmt.Fprintln(os.Stderr, "\nUSAGE")
		fmt.Fprintln(os.Stderr, "   form2email [options]")
		fs.PrintDefaults()
		fmt.Fprintln(os.Stderr, "\nEnv vars (overrides flags): SMTP_HOST, SMTP_FROM, SMTP_TO, SMTP_USER, SMTP_PASS")
	}

	if err := fs.Parse(os.Args[1:]); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			os.Exit(0)
		}
		fmt.Fprintln(os.Stderr, err)
		fs.Usage()
		os.Exit(1)
	}

	if cfg.showVersion {
		printVersion(os.Stdout)
		return
	}

	if cfg.smtpHost == "" || cfg.smtpFrom == "" || cfg.smtpToList == "" {
		fmt.Fprintf(os.Stderr, "\nError: missing required SMTP settings\n\n")
		fs.Usage()
		fmt.Fprintf(os.Stderr, "\nError: missing required SMTP settings\n\n")
		os.Exit(1)
	}
	printVersion(os.Stderr)

	// Verify templates are readable at startup; re-read on each request so
	// operators can edit HTML without restarting (matches legacy behavior).
	successFallback, err := os.ReadFile(cfg.successFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: couldn't read success response file %q: %v\n\n", cfg.successFile, err)
		os.Exit(1)
	}
	errorFallback, err := os.ReadFile(cfg.errorFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "\nError: couldn't read error response file %q: %v\n\n", cfg.errorFile, err)
		os.Exit(1)
	}
	successBody := hotReload(cfg.successFile, successFallback)
	errorBody := hotReload(cfg.errorFile, errorFallback)

	if cfg.smtpUser == "" {
		cfg.smtpUser = cfg.smtpFrom
	}
	if cfg.smtpFrom == "" {
		cfg.smtpFrom = cfg.smtpUser
	}

	if pass, hasPass := os.LookupEnv("SMTP_PASS"); !hasPass {
		fmt.Fprintf(os.Stderr, "SMTP_PASS not set → ")
		pwBytes, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			log.Fatalf("Failed to read password: %v", err)
		}
		fmt.Fprintln(os.Stderr)
		cfg.smtpPass = strings.TrimSpace(string(pwBytes))
	} else {
		cfg.smtpPass = pass
	}

	cfg.responseType = inferContentType(cfg.successFile)

	if cfg.cacheDir == "" {
		cfg.cacheDir = filepath.Join(home, ".cache")
	}

	// GeoIP config discovery: explicit --geoip-conf wins; otherwise default paths.
	if cfg.geoipConfPath == "" {
		for _, p := range geoip.DefaultConfPaths() {
			if _, err := os.Stat(p); err == nil {
				cfg.geoipConfPath = p
				break
			}
		}
	}
	if cfg.geoipConfPath == "" {
		log.Fatalf("geoip-conf: not found; set --geoip-conf or place GeoIP.conf in a default location.\n"+
			"GeoLite2 registration is free at https://www.maxmind.com/en/geolite2/signup\n"+
			"Default search paths: %v", geoip.DefaultConfPaths())
	}
	confData, err := os.ReadFile(cfg.geoipConfPath)
	if err != nil {
		log.Fatalf("geoip-conf: %v", err)
	}
	conf, err := geoip.ParseConf(string(confData))
	if err != nil {
		log.Fatalf("geoip-conf: %v", err)
	}
	geoipBasicAuth := httpcache.BasicAuth(conf.AccountID, conf.LicenseKey)

	// Blocklist: gitshallow-backed cohort, reloaded on each git HEAD change.
	repo := gitshallow.New(cfg.blocklistRepo, filepath.Join(cfg.cacheDir, "bitwire-it"), 1, "")
	repo.MaxAge = refreshInterval
	// Aggressive GC every 24 fetches (~roughly daily at 47min cadence).
	// bitwire-it auto-commits hourly with large blobs; without prune=now the
	// 2-week default grace window lets orphaned objects accumulate into GB.
	repo.GCInterval = 24
	blocklistSet := dataset.NewSet(repo)
	blacklist := dataset.AddInitial(blocklistSet, ipcohort.New(), func(_ context.Context) (*ipcohort.Cohort, error) {
		return ipcohort.LoadFiles(
			repo.FilePath("tables/inbound/single_ips.txt"),
			repo.FilePath("tables/inbound/networks.txt"),
		)
	})
	fmt.Fprint(os.Stderr, "Syncing git repo ... ")
	tBL := time.Now()
	if err := blocklistSet.Load(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr)
		fmt.Fprintf(os.Stderr, "error: ip cohort: %v\n", err)
	} else {
		fmt.Fprintf(os.Stderr, "%s (entries=%d)\n",
			time.Since(tBL).Round(time.Millisecond), blacklist.Value().Size())
	}

	// GeoIP: City + ASN tarballs via httpcache conditional GETs.
	maxmindDir := filepath.Join(cfg.cacheDir, "maxmind")
	authHeader := http.Header{"Authorization": []string{geoipBasicAuth}}
	geoSet := dataset.NewSet(
		&httpcache.Cacher{
			URL:    geoip.DownloadBase + "/GeoLite2-City/download?suffix=tar.gz",
			Path:   filepath.Join(maxmindDir, geoip.TarGzName(geoip.CityEdition)),
			MaxAge: 3 * 24 * time.Hour,
			Header: authHeader,
		},
		&httpcache.Cacher{
			URL:    geoip.DownloadBase + "/GeoLite2-ASN/download?suffix=tar.gz",
			Path:   filepath.Join(maxmindDir, geoip.TarGzName(geoip.ASNEdition)),
			MaxAge: 3 * 24 * time.Hour,
			Header: authHeader,
		},
	)
	geo := dataset.Add(geoSet, func(_ context.Context) (*geoip.Databases, error) {
		return geoip.Open(maxmindDir)
	})
	fmt.Fprint(os.Stderr, "Loading geoip... ")
	tGeo := time.Now()
	if err := geoSet.Load(context.Background()); err != nil {
		fmt.Fprintln(os.Stderr)
		log.Fatalf("geoip: %v", err)
	}
	fmt.Fprintf(os.Stderr, "%s\n", time.Since(tGeo).Round(time.Millisecond))

	fields := []formmailer.Field{
		{Label: "Name", FormName: "input_1", Kind: formmailer.KindText},
		{Label: "Email", FormName: "input_3", Kind: formmailer.KindEmail},
		{Label: "Phone", FormName: "input_4", Kind: formmailer.KindPhone},
		{Label: "Company", FormName: "input_5", Kind: formmailer.KindText},
		{Label: "Message", FormName: "input_7", Kind: formmailer.KindMessage},
	}
	fm := &formmailer.FormMailer{
		SMTPHost:    cfg.smtpHost,
		SMTPFrom:    cfg.smtpFrom,
		SMTPTo:      strings.Split(cfg.smtpToList, ","),
		SMTPUser:    cfg.smtpUser,
		SMTPPass:    cfg.smtpPass,
		Subject:     cfg.smtpSubject,
		SuccessBody: successBody,
		ErrorBody:   errorBody,
		ContentType: cfg.responseType,
		// Bot/blacklist rejections render {.SupportEmail} as "[REDACTED]"
		// rather than leaking the real address. Validation errors (wrong
		// format, missing field) still show the real support email so users
		// know where to write in.
		HiddenSupportValue: "[REDACTED]",
		// Only honor X-Forwarded-For from loopback (our reverse proxy runs
		// on the same host). Prevents spoofing rate limits and geo-gating.
		TrustedProxies: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
		},
		Blacklist: blacklist,
		Geo:       geo,
		// North America + unknown. Unknown ("") is always allowed by formmailer.
		AllowedCountries: []string{"US", "CA", "MX", "CR", "VI"},
		Fields:           fields,
		RPM:              requestsPerMinute,
		Burst:            burstSize,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	defer func() { _ = geoSet.Close() }()
	go blocklistSet.Tick(ctx, refreshInterval, func(err error) {
		log.Printf("blocklist refresh: %v", err)
	})
	go geoSet.Tick(ctx, refreshInterval, func(err error) {
		log.Printf("geoip refresh: %v", err)
	})

	mux := http.NewServeMux()
	emailFormName := ""
	for _, f := range fields {
		if f.Kind == formmailer.KindEmail {
			emailFormName = f.FormName
			break
		}
	}
	contact := silentDropRU(fm, emailFormName, successBody, cfg.responseType)
	mux.Handle("POST /contact", contact)
	mux.Handle("POST /contact/", contact)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintln(w, "form2email server running. POST form data to /contact")
	})

	srv := &http.Server{Addr: cfg.listenAddr, Handler: mux}

	fmt.Printf("form2email listening on http://%s\n", cfg.listenAddr)
	fmt.Printf("Forwarding submissions from %s → %s via %s\n", cfg.smtpFrom, cfg.smtpToList, cfg.smtpHost)
	fmt.Printf("Rate limit: ~%d req/min per IP (burst %d)\n", requestsPerMinute, burstSize)
	fmt.Println("CTRL+C to stop")

	serveErr := make(chan error, 1)
	go func() {
		if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			serveErr <- err
		}
		close(serveErr)
	}()

	select {
	case <-ctx.Done():
		log.Printf("shutdown: %v", ctx.Err())
	case err := <-serveErr:
		if err != nil {
			log.Fatalf("listen: %v", err)
		}
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	if err := srv.Shutdown(shutdownCtx); err != nil {
		log.Printf("shutdown: %v", err)
	}
}

// silentDropRU returns a handler that silently returns the success body for
// submissions whose email (emailFormName form input) ends with ".ru" —
// legacy spam-trap behavior from the original form2mail. All other
// submissions fall through to fm.
func silentDropRU(fm http.Handler, emailFormName string, successBody func() []byte, contentType string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// ParseMultipartForm is safe to call twice; formmailer will see the
		// already-parsed form. Use a bounded reader to match formmailer's cap.
		r.Body = http.MaxBytesReader(w, r.Body, 10*1024)
		if err := r.ParseMultipartForm(10 * 1024); err == nil {
			email := strings.ToLower(strings.TrimSpace(r.FormValue(emailFormName)))
			if strings.HasSuffix(email, ".ru") {
				w.Header().Set("Content-Type", contentType)
				_, _ = w.Write(successBody())
				return
			}
		}
		fm.ServeHTTP(w, r)
	})
}

// hotReload returns a function that re-reads path on each call, falling back
// to the provided bytes on read error (logged). Used for templates that
// operators may edit out-of-band.
func hotReload(path string, fallback []byte) func() []byte {
	return func() []byte {
		b, err := os.ReadFile(path)
		if err != nil {
			log.Printf("%s read: %v", path, err)
			return fallback
		}
		return b
	}
}

func inferContentType(path string) string {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".html", ".htm":
		return "text/html; charset=utf-8"
	case ".json":
		return "application/json"
	default:
		return "text/plain; charset=utf-8"
	}
}
