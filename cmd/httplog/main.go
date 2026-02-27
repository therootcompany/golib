package main

import (
	"bytes"
	"context"
	"encoding/json"
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
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/therootcompany/golib/colorjson"
)

const (
	name         = "httplog"
	licenseYear  = "2026"
	licenseOwner = "AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)"
	licenseType  = "CC0-1.0"
)

var (
	version = "0.1.0"
)

// printVersion displays the version, commit, and build date.
func printVersion(w io.Writer) {
	// _, _ = fmt.Fprintf(w, "%s v%s %s (%s)\n", name, version, commit[:7], date)
	_, _ = fmt.Fprintf(w, "%s v%s - log HTTP requests - headers, queries, body, etc\n", name, version)
	_, _ = fmt.Fprintf(w, "Copyright (C) %s %s\n", licenseYear, licenseOwner)
	_, _ = fmt.Fprintf(w, "Licensed under %s\n", licenseType)
}

type MainConfig struct {
	Bind        string
	Port        int
	ProxyTarget string
	ForceColor  bool
	jsonf       *colorjson.Formatter
}

func main() {
	cli := MainConfig{
		Bind:        "0.0.0.0",
		Port:        8080,
		ProxyTarget: "",
		ForceColor:  false,
		jsonf:       colorjson.NewFormatter(),
	}
	cli.jsonf.Indent = 3

	// Flags
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.IntVar(&cli.Port, "port", cli.Port, "port to listen on")
	fs.StringVar(&cli.Bind, "address", cli.Bind, "address to bind to (e.g. 127.0.0.1)")
	fs.StringVar(&cli.ProxyTarget, "proxy-target", cli.ProxyTarget, "upstream target to proxy requests to")
	fs.BoolVar(&cli.ForceColor, "color", false, "colorize output even if support is not detected (e.g. pipes, files)")

	if err := fs.Parse(os.Args[1:]); err != nil {
		if err == flag.ErrHelp {
			fs.Usage()
			os.Exit(0)
		}
		log.Fatalf("flag parse error: %v", err)
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

	if cli.ForceColor {
		// this is auto-detected
		color.NoColor = false
	}

	run(&cli)
}

func run(cli *MainConfig) {
	// Build proxy handler
	handleProxyToTarget := cli.newProxyHandler(cli.ProxyTarget)
	handler := cli.NewLogger(handleProxyToTarget)

	mux := http.NewServeMux()
	mux.Handle("HEAD /", handler)
	mux.Handle("OPTIONS /", handler)
	mux.Handle("GET /", handler)
	mux.Handle("POST /", handler)
	mux.Handle("PATCH /", handler)
	mux.Handle("PUT /", handler)
	mux.Handle("DELETE /", handler)

	// Server setup
	srv := &http.Server{
		Addr:              cli.Addr(),
		Handler:           mux,
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

	proxyTarget := cli.ProxyTarget
	if proxyTarget == "" {
		proxyTarget = "502 Bad Gateway"
	}
	log.Printf("Starting %s v%s on %s → %s", name, version, srv.Addr, proxyTarget)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		log.Fatalf("HTTP server failed: %v", err)
	}

	log.Println("Server stopped")
}

func (cli *MainConfig) Addr() string {
	return fmt.Sprintf("%s:%d", cli.Bind, cli.Port)
}

func (cli *MainConfig) NewLogger(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		var buf = new(bytes.Buffer)
		logURI(buf, r)
		logHeaders(buf, r.Host, r.Header)
		r.Body, err = cli.logBody(buf, r.Method, r.Header, r.Body)
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		log.Printf("[Request] Query, Headers, and Data:\n%s", buf.Bytes())

		next.ServeHTTP(w, r)
	})
}

func logURI(out io.Writer, r *http.Request) {
	// Log method, path, and query
	var query string
	if len(r.URL.RawQuery) > 0 {
		query = "?" + r.URL.RawQuery
	}
	_, _ = fmt.Fprintf(out, "%s %s%s\n", r.Method, r.URL.Path, query)

	// Print Query Params, if any
	if len(r.URL.RawQuery) > 0 {
		// Find max query name length for alignment
		var paramMaxLen int
		for param := range r.URL.Query() {
			if len(param) > paramMaxLen {
				paramMaxLen = len(param)
			}
		}
		paramMaxLen += 1

		queryParams := r.URL.Query()
		for param := range queryParams {
			for _, value := range queryParams[param] {
				_, _ = fmt.Fprintf(out, "   %-"+fmt.Sprintf("%d", paramMaxLen+1)+"s %s\n", param+" =", value)
			}
		}
		_, _ = fmt.Fprintf(out, "\n")
	}
}

func logHeaders(out io.Writer, host string, header http.Header) {
	// Find max header name length for alignment
	headerMaxLen := len("HOST")
	for name := range header {
		if len(name) > headerMaxLen {
			headerMaxLen = len(name)
		}
	}
	headerMaxLen += 1

	if host != "" {
		fmt.Fprintf(out, "   %-"+fmt.Sprintf("%d", headerMaxLen+1)+"s %s\n", "HOST", host)
	}
	for name, values := range header {
		for _, value := range values {
			fmt.Fprintf(out, "   %-"+fmt.Sprintf("%d", headerMaxLen+1)+"s %s\n", name+":", value)
		}
	}
	fmt.Fprintf(out, "\n")
}

func (cli *MainConfig) logBody(out io.Writer, method string, header http.Header, r io.ReadCloser) (io.ReadCloser, error) {
	rawBody, err := io.ReadAll(r)
	if method != "" {
		switch strings.ToUpper(method) {
		case "HEAD", "OPTIONS", "GET", "DELETE":
			if len(rawBody) > 0 {
				fmt.Fprintf(out, "Unexpected body:\n%q\n", string(rawBody))
			}
			return r, nil
		case "POST", "PATCH", "PUT":
			break
		default:
			fmt.Fprintf(out, "Unexpected method %q\n", method)
			return r, nil
		}
		defer fmt.Println()
	}

	// Read request body
	if err != nil {
		fmt.Fprintf(out, "Failed to read body:\n%q\n", string(rawBody))
		return r, err
	}
	nextBody := io.NopCloser(bytes.NewReader(rawBody))
	defer func() { _ = r.Close() }()

	// TODO: text/event-stream
	// Parse and pretty-print JSON, or raw body
	if strings.Contains(header.Get("Content-Type"), "json") {
		var text string
		var data any
		var b []byte
		if err := json.Unmarshal(rawBody, &data); err == nil {
			b, _ = cli.jsonf.Marshal(data)
		}

		text = string(b)
		text = prefixLines(text, "   ")
		text = strings.TrimSpace(text)
		fmt.Fprintf(out, "   %s\n", text)
	} else if strings.Contains(header.Get("Content-Type"), "text") {
		fmt.Fprintf(out, "   %s\n", string(rawBody))
	}

	return nextBody, nil
}

func prefixLines(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}

func (cli *MainConfig) newProxyHandler(targetURL string) http.Handler {
	if targetURL == "" {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("X-Logged-By", fmt.Sprintf("%s-v%s", name, version))
			w.WriteHeader(http.StatusBadGateway)
		})
	}

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
		ModifyResponse: func(resp *http.Response) error {
			var buf = new(bytes.Buffer)
			logHeaders(buf, "", resp.Header)
			resp.Body, err = cli.logBody(buf, "", resp.Header, resp.Body)
			if err != nil {
				return err
			}
			log.Printf("[Response] Headers & Data:\n%s", buf.Bytes())
			resp.Header.Set("X-Logged-By", fmt.Sprintf("%s-v%s", name, version))
			return nil
		},
		ErrorHandler: func(w http.ResponseWriter, r *http.Request, err error) {
			log.Printf("proxy error: %v", err)
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
		},
	}

	return proxy
}
