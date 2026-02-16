package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/therootcompany/golib/cmd/api-example/db"
	"github.com/therootcompany/golib/cmd/api-example/internal"
	"github.com/therootcompany/golib/crypto/passphrase"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/joho/godotenv"
)

const (
	name         = "CHANGE_ME"
	licenseYear  = "2025"
	licenseOwner = "AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)"
	licenseType  = "LICENSE in LICENSE"
)

// for goreleaser
var (
	version = ""
	commit  = ""
	date    = ""
)

var (
	newHTTPServer func(context.Context, string) (*http.Server, error)
)

func init() {
	// workaround for `tinygo` ldflag replacement handling not allowing default values
	// See <https://github.com/tinygo-org/tinygo/issues/2976>
	if len(version) == 0 {
		version = maybeGetVersion() // defaults to "0.0.0-dev"
	}
	if len(date) == 0 {
		date = maybeGetDate() // defaults to date-only "20xx-01-00 00:00:00"
	}
	if len(commit) == 0 {
		commit = maybeGetCommit() // defaults to "0000000"
	}
}

// printVersion displays the version, commit, and build date.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under the %s license\n", licenseType)
}

type MainConfig struct {
	defaultAddress       string
	defaultPort          int
	defaultProxyTarget   string
	address              string
	port                 int
	proxyTarget          string
	showVersion          bool
	pgURL                string
	encryptionPassphrase string
	encryptionSalt       string
}

func main() {
	cfg := MainConfig{
		defaultAddress:     "0.0.0.0",
		defaultPort:        3080,
		defaultProxyTarget: "127.0.0.1:3081",
	}

	var envErr error
	{
		envPath := peekOption(os.Args[1:], []string{"-envfile", "--envfile"}, ".env")

		if err := godotenv.Load(envPath); err != nil {
			if !errors.Is(err, os.ErrNotExist) {
				envErr = err
			}
		} else if err := parseEnvs(&cfg); err != nil {
			printVersion(os.Stderr)
			fmt.Fprintf(os.Stderr, "\nerror: %v\n", err)
		}
	}

	// note: --help is implicit, but handled specially below
	mainFlags := flag.NewFlagSet("", flag.ContinueOnError)
	mainFlags.BoolVar(&cfg.showVersion, "version", false, "Show version and exit")
	mainFlags.IntVar(&cfg.port, "port", cfg.defaultPort, "Port to listen on")
	_ = mainFlags.String("envfile", ".env", "Load ENVs from this file")
	mainFlags.StringVar(&cfg.pgURL, "pg-url", cfg.pgURL, "Postgres URL such as postgres://postgres@localhost:5432/postgres")
	mainFlags.StringVar(&cfg.proxyTarget, "proxy-target", cfg.defaultProxyTarget, "Proxy unhandled requests to this target")
	mainFlags.StringVar(&cfg.address, "address", cfg.defaultAddress, "Address to bind to")

	flagOut := os.Stderr
	mainFlags.Usage = func() {
		_, _ = fmt.Fprintf(flagOut, "USAGE\n")
		_, _ = fmt.Fprintf(flagOut, "   CHANGE_ME [options]\n")
		_, _ = fmt.Fprintf(flagOut, "\n")
		_, _ = fmt.Fprintf(flagOut, "EXAMPLES\n")
		_, _ = fmt.Fprintf(flagOut, "   CHANGE_ME --address 0.0.0.0 --port 443\n")
		_, _ = fmt.Fprintf(flagOut, "\n")
		_, _ = fmt.Fprintf(flagOut, "OPTIONS\n")
		mainFlags.PrintDefaults()
	}

	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "-V", "version", "-version", "--version":
			printVersion(os.Stdout)
			os.Exit(0)
			return
		case "help", "-help", "--help":
			printVersion(os.Stdout)
			_, _ = fmt.Fprintf(os.Stdout, "\n")

			flagOut = os.Stdout
			mainFlags.SetOutput(flagOut)
			mainFlags.Usage()
			os.Exit(0)
			return
		}
	}
	printVersion(os.Stderr)
	fmt.Fprintf(os.Stderr, "\n")

	if err := mainFlags.Parse(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)

		mainFlags.Usage()
		os.Exit(1)
		return
	}

	if envErr != nil {
		fmt.Fprintf(os.Stderr, "could not read .env: %s", envErr)
	}

	cfg.encryptionPassphrase = os.Getenv("APP_BIP39_PASSPHRASE")
	cfg.encryptionSalt = os.Getenv("APP_BIP39_SALT")
	run(&cfg)
}

func run(cfg *MainConfig) {
	var err error
	boottime, err := maybeGetUptime()
	if err != nil {
		log.Printf("could not get server uptime: %s", err)
	}

	// TODO: add signal handling for graceful shutdowns and restarts
	newHTTPServer = func(ctx context.Context, addr string) (*http.Server, error) {
		mux := http.NewServeMux()

		seed, _ := passphrase.SeedFrom(cfg.encryptionPassphrase, cfg.encryptionSalt)
		sensitiveKeyHex := hex.EncodeToString(seed)
		pgPool, err := configDB(cfg, ctx, sensitiveKeyHex)
		if err != nil {
			log.Fatalf("Error while creating new pgxpool: %s", err)
		}
		defer func() {
			pgPool.Close()
		}()

		api := &internal.API{
			BootTime:  boottime,
			StartTime: time.Now(),
			PG:        pgPool,
			Queries:   db.New(pgPool),
		}
		mux.HandleFunc("GET /api/status", api.HandleStatus)
		mux.HandleFunc("GET /api/hello", api.HandleGreet)
		mux.HandleFunc("GET /api/hello/{subject}", api.HandleGreet)

		proxy := internal.ProxyToOtherAPI(cfg.proxyTarget)
		mux.HandleFunc("OPTIONS /api/", proxy.ServeHTTP)
		mux.HandleFunc("GET /api/", proxy.ServeHTTP)
		mux.HandleFunc("POST /api/", proxy.ServeHTTP)
		mux.HandleFunc("PUT /api/", proxy.ServeHTTP)
		mux.HandleFunc("DELETE /api/", proxy.ServeHTTP)

		// allow http/1.1 and h2 from tls-terminating proxy
		protocols := &http.Protocols{}
		protocols.SetHTTP1(true)
		protocols.SetUnencryptedHTTP2(true)
		server := &http.Server{
			Addr:              addr,
			Handler:           mux,
			ReadHeaderTimeout: 10 * time.Second, // still needs per-request ReadTimeout
			WriteTimeout:      10 * time.Second,
			IdleTimeout:       (30 + 1) * time.Second,
			MaxHeaderBytes:    1 << 14, // 2^14 = 16k
			Protocols:         protocols,
		}

		return server, nil
	}

	addr := fmt.Sprintf("%s:%d", cfg.address, cfg.port)
	server, err := newHTTPServer(context.TODO(), addr)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Fprintf(os.Stderr, "Listening for http on %s\n", addr)
	err = server.ListenAndServe()
	log.Fatal(err)
}

func configDB(cfg *MainConfig, ctx context.Context, sensitiveKeyHex string) (*pgxpool.Pool, error) {
	pgConfig, err := pgxpool.ParseConfig(cfg.pgURL)
	if err != nil {
		log.Fatalf("Error while parsing PG_URL: %s", err)
	}

	// This runs for every **new** connection created by the pool
	pgConfig.AfterConnect = func(ctx context.Context, conn *pgx.Conn) error {
		// Escape the hex string properly for PostgreSQL bytea literal
		// \\x + hex digits is the standard way
		query := fmt.Sprintf("SET my.sensitive_data_key = '\\x%s';", sensitiveKeyHex)

		// Use Exec (no parameters needed here)
		_, err := conn.Exec(ctx, query)
		if err != nil {
			return fmt.Errorf("failed to set my.sensitive_data_key: %w", err)
		}

		// Optional: verify it (for debugging)
		// var val string
		// err = conn.QueryRow(ctx, "SHOW my.sensitive_data_key").Scan(&val)
		// log.Printf("After set: %s", val)

		return nil
	}

	return pgxpool.NewWithConfig(ctx, pgConfig)
}
