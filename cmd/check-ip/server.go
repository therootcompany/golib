package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/therootcompany/golib/net/geoip"
)

const shutdownTimeout = 5 * time.Second

// serve runs the HTTP API until ctx is cancelled, shutting down gracefully.
//
//	GET /         checks the request's client IP
//	GET /check    same, plus ?ip= overrides
//
// Response format is chosen per request: ?format=json, then
// Accept: application/json, else pretty text.
func serve(ctx context.Context, bind string, checker *Checker) error {
	handle := func(w http.ResponseWriter, r *http.Request, ip string) {
		format := requestFormat(r)
		if format == formatJSON {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		writeResult(w, checker.Check(ip), format)
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
		Addr:    bind,
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

	fmt.Fprintf(os.Stderr, "listening on %s\n", bind)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// format is the response rendering. Server-only.
type format int

const (
	formatPretty format = iota
	formatJSON
)

// requestFormat picks a response format from ?format=, then Accept header.
func requestFormat(r *http.Request) format {
	switch r.URL.Query().Get("format") {
	case "json":
		return formatJSON
	case "pretty":
		return formatPretty
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return formatJSON
	}
	return formatPretty
}

func writeResult(w io.Writer, r Result, f format) {
	if f == formatJSON {
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(r)
		return
	}
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
