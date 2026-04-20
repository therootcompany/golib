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
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/dataset"
)

const shutdownTimeout = 5 * time.Second

// Result is the structured verdict for a single IP.
type Result struct {
	IP              string     `json:"ip"`
	Blocked         bool       `json:"blocked"`
	BlockedInbound  bool       `json:"blocked_inbound"`
	BlockedOutbound bool       `json:"blocked_outbound"`
	Geo             geoip.Info `json:"geo,omitzero"`
}

// serve runs the HTTP API until ctx is cancelled.
//
//	GET /         checks the request's client IP
//	GET /check    same, plus ?ip= overrides
//
// Response format: ?format=json, then Accept: application/json, else pretty.
func serve(
	ctx context.Context,
	bind string,
	inbound, outbound *dataset.View[ipcohort.Cohort],
	geo *geoip.Databases,
) error {
	check := func(ip string) Result {
		in := inbound.Value().Contains(ip)
		out := outbound.Value().Contains(ip)
		return Result{
			IP:              ip,
			Blocked:         in || out,
			BlockedInbound:  in,
			BlockedOutbound: out,
			Geo:             geo.Lookup(ip),
		}
	}

	handle := func(w http.ResponseWriter, r *http.Request, ip string) {
		f := requestFormat(r)
		if f == formatJSON {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		write(w, check(ip), f)
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

func write(w io.Writer, r Result, f format) {
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
	var parts []string
	if r.Geo.City != "" {
		parts = append(parts, r.Geo.City)
	}
	if r.Geo.Region != "" {
		parts = append(parts, r.Geo.Region)
	}
	if r.Geo.Country != "" {
		parts = append(parts, fmt.Sprintf("%s (%s)", r.Geo.Country, r.Geo.CountryISO))
	}
	if len(parts) > 0 {
		fmt.Fprintf(w, "  Location: %s\n", strings.Join(parts, ", "))
	}
	if r.Geo.ASN != 0 {
		fmt.Fprintf(w, "  ASN:      AS%d %s\n", r.Geo.ASN, r.Geo.ASNOrg)
	}
}

// clientIP extracts the caller's IP, honoring X-Forwarded-For when present.
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
