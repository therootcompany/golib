// auth-proxy - A reverse proxy to require Basic Auth, Bearer Token, or access_token
//
// Copyright 2026 AJ ONeal <aj@therootcompany.com>
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// This Source Code Form is "Incompatible With Secondary Licenses", as
// defined by the Mozilla Public License, v. 2.0.
//
// SPDX-License-Identifier: MPL-2.0

package main

import (
	"context"
	"encoding/hex"
	"errors"
	"flag"
	"fmt"
	"io"
	"iter"
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
	"unicode/utf8"

	"github.com/joho/godotenv"

	"github.com/therootcompany/golib/auth"
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

// printVersion displays the version, commit, and build date.
func printVersion(w io.Writer) {
	_, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

var (
	ErrNoAuth = errors.New("request missing the required form of authorization")
)

var creds *csvauth.Auth

const basicAPIKeyName = ""

type MainConfig struct {
	Address                    string
	Port                       int
	CredentialsPath            string
	ProxyTarget                string
	AES128KeyPath              string
	ShowVersion                bool
	AuthorizationHeaderSchemes []string
	TokenHeaderNames           []string
	QueryParamNames            []string
	comma                      rune
	commaString                string
	tokenSchemeList            string
	tokenHeaderList            string
	tokenParamList             string
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
		AES128KeyPath:              filepath.Join("~", ".config", "csvauth", "aes-128.key"),
		comma:                      '\t',
		commaString:                "",
		tokenSchemeList:            "",
		tokenHeaderList:            "",
		tokenParamList:             "",
		AuthorizationHeaderSchemes: nil, // []string{"Bearer", "Token"}
		TokenHeaderNames:           nil, // []string{"X-API-Key", "X-Auth-Token", "X-Access-Token"},
		QueryParamNames:            nil, // []string{"access_token", "token"},
	}

	// Peek for --envfile early
	envPath := peekOption(os.Args[1:], []string{"-envfile", "--envfile"}, ".env")
	_ = godotenv.Load(envPath) // silent if missing

	// Override defaults from env
	if v := os.Getenv("AUTHPROXY_PORT"); v != "" {
		if _, err := fmt.Sscanf(v, "%d", &cli.Port); err != nil {
			fmt.Fprintf(os.Stderr, "invalid AUTHPROXY_PORT value: %s\n", v)
			os.Exit(1)
		}
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
	fs.StringVar(&cli.AES128KeyPath, "aes-128-key", cli.AES128KeyPath, "path to credentials TSV/CSV file")
	fs.StringVar(&cli.CredentialsPath, "credentials", cli.CredentialsPath, "path to credentials TSV/CSV file")
	fs.StringVar(&cli.ProxyTarget, "proxy-target", cli.ProxyTarget, "upstream target to proxy requests to")
	fs.StringVar(&cli.commaString, "comma", "\\t", "single-character CSV separator for credentials file (literal characters and escapes accepted)")
	fs.StringVar(&cli.tokenSchemeList, "token-schemes", "Bearer,Token", "checks for header 'Authorization: <Scheme> <token>'")
	fs.StringVar(&cli.tokenHeaderList, "token-headers", "X-API-Key,X-Auth-Token,X-Access-Token", "checks for header '<API-Key-Header>: <token>'")
	fs.StringVar(&cli.tokenParamList, "token-params", "access_token,token", "checks for query param '?<param>=<token>'")

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
			_, _ = fmt.Fprintln(os.Stdout, "")
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

	{
		homedir, err := os.UserHomeDir()
		if err == nil {
			var found bool
			if cli.AES128KeyPath, found = strings.CutPrefix(cli.AES128KeyPath, "~"); found {
				cli.AES128KeyPath = homedir + cli.AES128KeyPath
			}
		}
	}

	// credentials file delimiter
	var err error
	cli.comma, err = DecodeDelimiter(cli.commaString)
	if err != nil {
		log.Fatalf("comma parse error: %v", err)
	}

	// Authorization: <Scheme> <token>
	cli.tokenSchemeList = strings.TrimSpace(cli.tokenSchemeList)
	if cli.tokenSchemeList != "" && cli.tokenSchemeList != "none" {
		cli.tokenSchemeList = strings.ReplaceAll(cli.tokenSchemeList, ",", " ")
		cli.AuthorizationHeaderSchemes = strings.Fields(cli.tokenSchemeList)
		if len(cli.AuthorizationHeaderSchemes) == 1 && cli.AuthorizationHeaderSchemes[0] == "" {
			cli.AuthorizationHeaderSchemes = nil
		}
	}

	// <API-Key-Header>: <token>
	// trick: this allows `Authorization: <token>` without the scheme
	cli.tokenHeaderList = strings.TrimSpace(cli.tokenHeaderList)
	if cli.tokenHeaderList != "" && cli.tokenHeaderList != "none" {
		cli.tokenHeaderList = strings.ReplaceAll(cli.tokenHeaderList, ",", " ")
		cli.TokenHeaderNames = strings.Fields(cli.tokenHeaderList)
		if len(cli.TokenHeaderNames) == 1 && cli.TokenHeaderNames[0] == "" {
			cli.TokenHeaderNames = nil
		}
	}

	// ?<param>=<token>
	// trick: this allows `Authorization: <token>` without the scheme
	cli.tokenParamList = strings.TrimSpace(cli.tokenParamList)
	if cli.tokenParamList != "" && cli.tokenParamList != "none" {
		cli.tokenParamList = strings.ReplaceAll(cli.tokenParamList, ",", " ")
		cli.QueryParamNames = strings.Fields(cli.tokenParamList)
		if len(cli.QueryParamNames) == 1 && cli.QueryParamNames[0] == "" {
			cli.QueryParamNames = nil
		}
	}

	run(&cli)
}

const (
	fileSeparator   = '\x1c'
	groupSeparator  = '\x1d'
	recordSeparator = '\x1e'
	unitSeparator   = '\x1f'
)

func DecodeDelimiter(delimString string) (rune, error) {
	switch delimString {
	case "^_", "\\x1f":
		delimString = string(unitSeparator)
	case "^^", "\\x1e":
		delimString = string(recordSeparator)
	case "^]", "\\x1d":
		delimString = string(groupSeparator)
	case "^\\", "\\x1c":
		delimString = string(fileSeparator)
	case "^L", "\\f":
		delimString = "\f"
	case "^K", "\\v":
		delimString = "\v"
	case "^I", "\\t":
		delimString = "\t"
	default:
		// it is what it is
	}
	delim, _ := utf8.DecodeRuneInString(delimString)
	return delim, nil
}

func run(cli *MainConfig) {
	defaultAESKeyENVName := "CSVAUTH_AES_128_KEY"
	aesKey, err := getAESKey(defaultAESKeyENVName, cli.AES128KeyPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err)
		os.Exit(1)
		return
	}

	// Load credentials from CSV/TSV file once at startup
	f, err := os.Open(cli.CredentialsPath)
	if err != nil {
		log.Fatalf("Failed to open credentials file %q: %v", cli.CredentialsPath, err)
	}
	defer func() { _ = f.Close() }()

	creds = csvauth.New(aesKey)
	if err := creds.LoadCSV(f, cli.comma); err != nil {
		log.Fatalf("Failed to load CSV auth: %v", err)
	}

	var usableRoles int
	for key := range creds.CredentialKeys() {
		u, err := creds.LoadCredential(key)
		if err != nil {
			log.Fatalf("Failed to read users from CSV auth: %v", err)
		}
		if len(u.Roles) == 0 {
			continue
		}
		if usableRoles == 0 {
			fmt.Fprintf(os.Stderr, "Current credentials, tokens, and permissions:\n")
		}
		fmt.Fprintf(os.Stderr, "    %s\t%s\t%s\n", u.Purpose, u.ID(), strings.Join(u.Roles, " "))
		usableRoles += 1
	}

	var warnRoles bool
	for key := range creds.CredentialKeys() {
		u, _ := creds.LoadCredential(key)
		if len(u.Roles) > 0 {
			continue
		}
		if !warnRoles {
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "WARNING - Please Read\n")
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "\n")
			fmt.Fprintf(os.Stderr, "The following credentials cannot be used because they contain no Roles:\n")
			warnRoles = true
		}
		fmt.Fprintf(os.Stderr, "   %q (%s)\n", u.Name, u.Purpose)
	}
	if warnRoles {
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "Permission must be explicitly granted in the Roles column as a space-separated\n")
		fmt.Fprintf(os.Stderr, "list of URI matchers in the form of \"[METHOD:][HOST]/[PATH]\"\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "CLI Examples\n")
		fmt.Fprintf(os.Stderr, "   authcsv store --roles '/' john.doe\n")
		fmt.Fprintf(os.Stderr, "   authcsv store --roles 'GET:example.com/mail POST:example.com/feed' --token openclaw\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "CSV Examples\n")
		fmt.Fprintf(os.Stderr, "   GET:example.com/           # GET-only access to example.com, for all paths\n")
		fmt.Fprintf(os.Stderr, "   /                          # Full access to everything\n")
		fmt.Fprintf(os.Stderr, "   GET:/ POST:/logs           # GET anything, POST only to /logs/... \n")
		fmt.Fprintf(os.Stderr, "   ex1.com/ GET:ex2.net/logs  # full access to ex1.com, GET-only for ex2.net\n")
		fmt.Fprintf(os.Stderr, "\n")
		fmt.Fprintf(os.Stderr, "\n")
	}
	if usableRoles == 0 {
		fmt.Fprintf(os.Stderr, "Error: no usable credentials found\n")
		os.Exit(1)
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
		if !cli.authorize(r) {
			// TODO allow --realm for `WWW-Authenticate: Basic realm="My Application"`
			w.Header().Set("WWW-Authenticate", `Basic`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		proxy.ServeHTTP(w, r)
	})
}

func (cli *MainConfig) authorize(r *http.Request) bool {
	cred, err := cli.authenticate(r)
	if err != nil {
		if !errors.Is(err, ErrNoAuth) {
			return false
		}
		cred, err = creds.Authenticate("guest", "")
		if err != nil {
			return false
		}
	}

	grants := cred.Permissions()
	if len(grants) == 0 {
		// must have at least '/'
		fmt.Fprintf(os.Stderr, "Warn: user %q correctly authenticated, but no --roles were specified (assign * or / for full access)\n", cred.ID())
		return false
	}

	if grants[0] == "*" || grants[0] == "/" {
		return true
	}

	// GET,POST example.com/path/{$}
	for _, grant := range grants {
		if matchPattern(grant, r.Method, r.Host, r.URL.Path) {
			return true
		}
	}

	return false
}

// patternMatch returns true for a grant in the form of a ServeMux pattern matches the current request
// (though : is used instead of space since space is already used as a separator)
//
// grant is in the form `[METHOD:][HOST]/[PATH]`, but METHOD may be a comma-separated list GET,POST...
// rMthod must be ALL_CAPS
// rHost may be HOSTNAME or HOSTNAME:PORT
// rPath must start with /
func matchPattern(grant, rMethod, rHost, rPath string) bool {
	// this should have been done already, but...
	grant = strings.TrimSpace(grant)

	// must have at least /
	// ""
	if grant == "" {
		fmt.Fprintf(os.Stderr, "DEBUG: missing grant\n")
		return false
	}

	// / => ["/"]
	// /path => ["/path"]
	// example.com/path => ["example.com/path"]
	// GET:example.com/path => ["GET", "example.com/path"]
	{
		var methodSep = ":"
		var methods []string
		grantParts := strings.SplitN(grant, methodSep, 2)
		switch len(grantParts) {
		case 1:
			// no method
		case 2:
			if len(grantParts) == 2 {
				methods = strings.Split(strings.ToUpper(grantParts[0]), ",")
				if !slices.Contains(methods, rMethod) {
					// TODO maybe propagate method-not-allowed?
					fmt.Fprintf(os.Stderr, "DEBUG: method %q != %q\n", rMethod, grantParts[0])
					return false
				}
				grant = grantParts[1]
			}
		default:
			fmt.Fprintf(os.Stderr, "DEBUG: extraneous spaces in grant %q\n", grant)
			return false
		}
	}

	// / => /
	// /path => /path
	// example.com/path => /path
	idx := strings.Index(grant, "/")
	if idx < 0 {
		// host without path is invalid
		fmt.Fprintf(os.Stderr, "DEBUG: missing leading / from grant %q\n", grant)
		return false
	}
	hostname := grant[:idx]
	if hostname != "" {
		// example.com:443 => example.com
		if h, _, _ := strings.Cut(rHost, ":"); hostname != h {
			// hostname doesn't match
			fmt.Fprintf(os.Stderr, "DEBUG: hostname %q != %q\n", rHost, hostname)
			return false
		}
	}
	grant = grant[idx:]

	// Prefix-only matching
	//
	// /path => /path
	// /path/ => /path
	// /path/{var}/bar => /path/{var}/bar
	// /path/{var...} = /path/{var}
	// /path/{$} => /path
	// var exact bool
	// grant, exact = strings.CutSuffix(grant, "/{$}")
	// grant, _ = strings.CutSuffix(grant, "/")
	// rPath, _ = strings.CutSuffix(rPath, "/")
	// if len(grantPaths) > len(rPaths) {
	// 	return false
	// } else if len(grantPaths) < len(rPaths) {
	// 	if exact {
	// 		return false
	// 	}
	// }

	// // TODO replace with pattern matching as per https://pkg.go.dev/net/http#hdr-Patterns-ServeMux
	// // /path/{var}/bar matches /path/foo/bar and /path/foo/bar/
	// // /path/{var...} matches /path/ and /path/foo/bar
	// // /path/{var}/bar/{$} matches /path/foo/bar and /path/baz/bar/ but not /path/foo/
	// for i := 1; i < len(grantPaths); i++ {
	// 	grantPath := grantPaths[i]
	// 	rPath := rPaths[i]
	// 	if strings.HasPrefix(grantPath, "{") {
	// 		continue
	// 	}
	// 	if rPath != grantPath {
	// 		return false
	// 	}
	// }
	// return true

	// ServeMux pattern matching
	nextGPath, gstop := iter.Pull(strings.SplitSeq(grant, "/"))
	nextRPath, rstop := iter.Pull(strings.SplitSeq(rPath, "/"))
	defer gstop()
	defer rstop()

	for {
		gp, gok := nextGPath()
		rp, rok := nextRPath()
		// everything has matched thus far, and the pattern has ended
		if !gok {
			return true
		}

		// false unless the extra length of the pattern signifies the exact match, disregarding trailing /
		if !rok {
			// this matches trailing /, {var}, {var}/, {var...}, and {$}
			if gp == "" || (strings.HasPrefix(gp, "{") && strings.HasSuffix(gp, "}")) {
				gp2, more := nextGPath()
				// this allows for one more final trailing /, but nothing else
				if !more {
					return true
				}
				if gp2 == "" {
					// two trailing slashes are not allowed
					_, more := nextGPath()
					return !more
				}
			}
			return false
		}

		// path parts are only allowed to disagree for trailing slashes and variables
		if gp != rp {
			// this allows for one more final trailing / on the pattern, but nothing else
			if gp == "" {
				_, more := nextGPath()
				return !more
			}
			// this allows for a placeholder in the pattern
			if strings.HasPrefix(gp, "{") && strings.HasSuffix(gp, "}") {
				// normal variables pass
				if gp != "{$}" {
					continue
				}
				// trailing slash on exact match passes
				if rp == "" {
					_, more := nextRPath()
					return !more
				}
				fmt.Fprintf(os.Stderr, "DEBUG: path past {$} %q vs %q\n", rp, gp)
				return false
			}
			fmt.Fprintf(os.Stderr, "DEBUG: path part %q != %q\n", rp, gp)
			return false
		}
	}
}

func (cli *MainConfig) authenticate(r *http.Request) (auth.BasicPrinciple, error) {
	// 1. Try Basic Auth first (cleanest path)
	username, password, ok := r.BasicAuth()
	if ok {
		// Authorization: Basic <Auth> exists
		return creds.Authenticate(username, password)
	}

	// 2. Any Authorization: <scheme> <token>
	if len(cli.AuthorizationHeaderSchemes) > 0 {
		authHeader := r.Header.Get("Authorization")
		if authHeader != "" {
			parts := strings.SplitN(authHeader, " ", 2)
			if len(parts) == 2 {
				if cli.AuthorizationHeaderSchemes[0] == "*" ||
					slices.Contains(cli.AuthorizationHeaderSchemes, parts[0]) {
					token := strings.TrimSpace(parts[1])
					// Authorization: <Scheme> <Token> exists
					return creds.Authenticate(basicAPIKeyName, token)
				}
			}
			return nil, errors.New("'Authorization' header is not properly formatted")
		}
	}

	// 3. API-Key / X-API-Key headers
	for _, h := range cli.TokenHeaderNames {
		if key := r.Header.Get(h); key != "" {
			// <TokenHeader>: <Token> exists
			return creds.Authenticate(basicAPIKeyName, key)
		}
	}

	// 4. access_token query param
	for _, h := range cli.QueryParamNames {
		if token := r.URL.Query().Get(h); token != "" {
			// <query_param>?=<Token> exists
			return creds.Authenticate(basicAPIKeyName, token)
		}
	}

	return nil, ErrNoAuth
}

// peekOption looks for a flag value without parsing the full set
func peekOption(args []string, names []string, def string) string {
	for i := range len(args) {
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
