// envtocsv - Converts one or more .env files into a merged, sorted CSV
//
// Authored in 2026 by AJ ONeal <aj@therootcompany.com> w/ Grok (https://grok.com).
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

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
	"net/http/httputil"
	"net/url"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/joho/godotenv"
	"github.com/therootcompany/golib/auth/csvauth"
)

const (
	name         = "auth-proxy"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)"
	licenseType  = "CC0-1.0"
)

// replaced by goreleaser / ldflags
var (
	version = "0.0.0-dev"
	commit  = "0000000"
	date    = "0001-01-01"
)

// auth is loaded once at startup and used by all requests
var auth *csvauth.Auth

// printVersion displays the version, commit, and build date.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

type MainConfig struct {
	Address                    string
	Port                       int
	CredentialsPath            string
	ProxyTarget                string
	ShowVersion                bool
	TokenHeaderNames           []string
	AuthorizationHeaderSchemes []string
}

func (c *MainConfig) Addr() string {
	return fmt.Sprintf("%s:%d", c.Address, c.Port)
}

func main() {
	cli := MainConfig{
		Address:                    "0.0.0.0",
		Port:                       8081,
		CredentialsPath:            "./credentials.tsv",
		ProxyTarget:                "http://127.0.0.1:8080",
		AuthorizationHeaderSchemes: []string{"*"}, // Bearer, Token, APIKey, etc
		TokenHeaderNames:           []string{"API-Key", "X-API-Key"},
	}

	// Peek for --envfile early
	envPath := peekOption(os.Args[1:], []string{"-envfile", "--envfile"}, ".env")
	_ = godotenv.Load(envPath) // silent if missing

	// Override defaults from env
	if v := os.Getenv("AUTHPROXY_PORT"); v != "" {
		fmt.Sscanf(v, "%d", &cli.Port)
	}
	if v := os.Getenv("AUTHPROXY_ADDRESS"); v != "" {
		cli.Address = v
	}
	if v := os.Getenv("AUTHPROXY_CREDENTIALS_FILE"); v != "" {
		cli.CredentialsPath = v
	}
	if v := os.Getenv("AUTHPROXY_TARGET"); v != "" {
		cli.ProxyTarget = v
	}

	// Flags
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.BoolVar(&cli.ShowVersion, "version", false, "show version and exit")
	fs.IntVar(&cli.Port, "port", cli.Port, "port to listen on")
	fs.StringVar(&cli.Address, "address", cli.Address, "address to bind to (e.g. 127.0.0.1)")
	fs.StringVar(&cli.CredentialsPath, "credentials", cli.CredentialsPath, "path to credentials TSV/CSV file")
	fs.StringVar(&cli.ProxyTarget, "proxy-target", cli.ProxyTarget, "upstream target to proxy requests to")

	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "USAGE\n  %s [flags]\n\n", name)
		fmt.Fprintf(os.Stderr, "FLAGS\n")
		fs.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nENVIRONMENT\n")
		fmt.Fprintf(os.Stderr, "  AUTHPROXY_PORT              port to listen on\n")
		fmt.Fprintf(os.Stderr, "  AUTHPROXY_ADDRESS           bind address\n")
		fmt.Fprintf(os.Stderr, "  AUTHPROXY_CREDENTIALS_FILE  path to tokens file\n")
		fmt.Fprintf(os.Stderr, "  AUTHPROXY_TARGET            upstream URL\n")
	}

	// Special handling for version/help
	if len(os.Args) > 1 {
		arg := os.Args[1]
		if arg == "-V" || arg == "--version" || arg == "version" {
			printVersion(os.Stdout)
			os.Exit(0)
		}
		if arg == "help" || arg == "-help" || arg == "--help" {
			printVersion(os.Stdout)
			fmt.Fprintln(os.Stdout, "")
			fs.SetOutput(os.Stdout)
			fs.Usage()
			os.Exit(0)
		}
	}

	printVersion(os.Stderr)
	fmt.Fprintln(os.Stderr, "")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			fs.Usage()
			os.Exit(0)
		}
		log.Fatalf("flag parse error: %v", err)
	}

	run(&cli)
}

func run(cli *MainConfig) {
	// TODO handle better
	defaultAESKeyENVName := "CSVAUTH_AES_128_KEY"
	keyRelPath := filepath.Join(".config", "csvauth", "aes-128.key")
	homedir, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
		return
	}
	filename := filepath.Join(homedir, keyRelPath)
	aesKey, keyErr := getAESKey(defaultAESKeyENVName, filename)
	if keyErr != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
		return
	}

	// Load credentials from CSV/TSV file once at startup
	f, err := os.Open(cli.CredentialsPath)
	if err != nil {
		log.Fatalf("Failed to open credentials file %q: %v", cli.CredentialsPath, err)
	}
	defer f.Close()

	auth = csvauth.New(aesKey)
	if err := auth.LoadCSV(f, '\t'); err != nil {
		log.Fatalf("Failed to load CSV auth: %v", err)
	}

	// Build proxy handler
	handler := cli.newAuthProxyHandler(cli.ProxyTarget)

	// Server setup
	srv := &http.Server{
		Addr:              cli.Addr(),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}

	// Graceful shutdown
	done := make(chan os.Signal, 1)
	signal.Notify(done, os.Interrupt, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-done
		log.Println("Shutting down server...")
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		if err := srv.Shutdown(ctx); err != nil {
			log.Printf("HTTP server shutdown error: %v", err)
		}
	}()

	log.Printf("Starting %s v%s on %s → %s", name, version, srv.Addr, cli.ProxyTarget)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v", err)
	}

	log.Println("Server stopped")
}

func (cli *MainConfig) newAuthProxyHandler(targetURL string) http.Handler {
	target, err := url.Parse(targetURL)
	if err != nil {
		log.Fatalf("invalid proxy target %q: %v", targetURL, err)
	}

	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			r.SetURL(target)
			r.Out.Host = r.In.Host // preserve original Host header
			// X-Forwarded-* headers are preserved from incoming request
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !cli.authenticate(r) {
			// w.Header().Set("WWW-Authenticate", `Basic realm="API", Bearer`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func (cli *MainConfig) authenticate(r *http.Request) bool {
	// 1. Try Basic Auth first (cleanest path)
	username, password, ok := r.BasicAuth()
	if ok {
		fmt.Println("DEBUG Basic Auth", username, password)
		if auth.Verify(username, password) != nil {
			// Authorization: Basic <Auth> exists and is not valid
			return false
		}
		return true
	}

	// 2. Any Authorization: <scheme> <token>
	if len(cli.AuthorizationHeaderSchemes) > 0 {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			fmt.Println("DEBUG Authorization", parts)
			if len(parts) == 2 {
				if cli.AuthorizationHeaderSchemes[0] == "*" ||
					slices.Contains(cli.AuthorizationHeaderSchemes, parts[0]) {
					token := strings.TrimSpace(parts[1])
					if auth.VerifyToken(token) == nil {
						return true
					}
				}
			}
			// Authorization: <Scheme> <Token> exists and is not valid
			return false
		}
	}

	// 3. API-Key / X-API-Key headers
	for _, h := range cli.TokenHeaderNames {
		if key := r.Header.Get(h); key != "" {
			fmt.Println("DEBUG Token Header", h, key)
			if err := auth.VerifyToken(key); err != nil {
				// <TokenHeader>: <Token> exists and is not valid
				return false
			}
			return true
		}
	}

	return false
}

// peekOption looks for a flag value without parsing the full set
func peekOption(args []string, names []string, def string) string {
	for i := 0; i < len(args); i++ {
		for _, name := range names {
			if args[i] == name {
				if i+1 < len(args) {
					return args[i+1]
				}
			}
		}
	}
	return def
}

// TODO expose this from csvauth
func getAESKey(envname, filename string) ([]byte, error) {
	envKey := os.Getenv(envname)
	if envKey != "" {
		key, err := hex.DecodeString(strings.TrimSpace(envKey))
		if err != nil || len(key) != 16 {
			return nil, fmt.Errorf("invalid %s: must be 32-char hex string", envname)
		}
		fmt.Fprintf(os.Stderr, "Found AES Key in %s\n", envname)
		return key, nil
	}

	if _, err := os.Stat(filename); err != nil {
		return nil, err
	}

	data, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read %s: %v", filename, err)
	}
	key, err := hex.DecodeString(strings.TrimSpace(string(data)))
	if err != nil || len(key) != 16 {
		return nil, fmt.Errorf("invalid key in %s: must be 32-char hex string", filename)
	}
	// relpath := strings.Replace(filename, homedir, "~", 1)
	fmt.Fprintf(os.Stderr, "Found AES Key at %s\n", filename)
	return key, nil
}
