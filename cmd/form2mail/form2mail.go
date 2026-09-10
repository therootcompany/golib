package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"

	"github.com/joho/godotenv"

	"github.com/therootcompany/golib/net/formmailer"
)

const (
	name         = "form2email"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal"
	licenseType  = "CC0-1.0"

	defaultBlocklistRepo = "https://github.com/bitwire-it/ipblocklist.git"

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
	blocklistRepo string
	cacheDir      string
	geoipDir      string
	geoipBaseURL  string
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
	fs.StringVar(&cfg.geoipDir, "geoip-dir", "", "dir holding GeoLite2 tarballs (default: <$cache-dir>/maxmind)")
	fs.StringVar(&cfg.geoipBaseURL, "geoip-base-url", "", "MaxMind download base URL (default: https://download.maxmind.com/geoip/databases)")
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

	// Build FormMailer — all blocklist/GeoIP setup is handled by Run().
	fields := []formmailer.Field{
		{Label: "Name", FormName: "input_1", Kind: formmailer.KindText},
		{Label: "Email", FormName: "input_3", Kind: formmailer.KindEmail},
		{Label: "Phone", FormName: "input_4", Kind: formmailer.KindPhone},
		{Label: "Company", FormName: "input_5", Kind: formmailer.KindText},
		{Label: "Message", FormName: "input_7", Kind: formmailer.KindMessage},
	}

	fm := &formmailer.FormMailer{
		ListenAddr:         cfg.listenAddr,
		SMTPHost:           cfg.smtpHost,
		SMTPFrom:           cfg.smtpFrom,
		SMTPTo:             strings.Split(cfg.smtpToList, ","),
		SMTPUser:           cfg.smtpUser,
		SMTPPass:           cfg.smtpPass,
		Subject:            cfg.smtpSubject,
		SuccessBody:        successBody,
		ErrorBody:          errorBody,
		ContentType:        inferContentType(cfg.successFile),
		HiddenSupportValue: "[REDACTED]",
		TrustedProxies: []netip.Prefix{
			netip.MustParsePrefix("127.0.0.0/8"),
			netip.MustParsePrefix("::1/128"),
			netip.MustParsePrefix("10.0.0.0/8"),
			netip.MustParsePrefix("172.16.0.0/12"),
			netip.MustParsePrefix("192.168.0.0/16"),
		},
		BlocklistRepo:    cfg.blocklistRepo,
		CacheDir:         cfg.cacheDir,
		GeoIPDir:         cfg.geoipDir,
		GeoIPBaseURL:     cfg.geoipBaseURL,
		GeoIPConfPath:    cfg.geoipConfPath,
		AllowedCountries: []string{"US", "CA", "MX", "CR", "VI"},
		Fields:           fields,
		RPM:              requestsPerMinute,
		Burst:            burstSize,
	}

	if err := fm.Run(context.Background()); err != nil {
		log.Fatalf("server: %v", err)
	}
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
