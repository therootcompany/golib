package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/therootcompany/golib/net/geoip"
	"github.com/therootcompany/golib/net/ipcohort"
	"github.com/therootcompany/golib/sync/dataset"
)

// Result is the JSON verdict for a single IP.
type Result struct {
	IP              string     `json:"ip"`
	Blocked         bool       `json:"blocked"`
	BlockedInbound  bool       `json:"blocked_inbound"`
	BlockedOutbound bool       `json:"blocked_outbound"`
	Geo             geoip.Info `json:"geo,omitzero"`
}

func serve(
	ctx context.Context,
	bind string,
	inbound, outbound *dataset.View[ipcohort.Cohort],
	geo *geoip.Databases,
) error {
	handle := func(w http.ResponseWriter, r *http.Request) {
		ip := strings.TrimSpace(r.URL.Query().Get("ip"))
		if ip == "" {
			ip = clientIP(r)
		}
		in := inbound.Value().Contains(ip)
		out := outbound.Value().Contains(ip)
		res := Result{
			IP:              ip,
			Blocked:         in || out,
			BlockedInbound:  in,
			BlockedOutbound: out,
			Geo:             geo.Lookup(ip),
		}

		if r.URL.Query().Get("format") == "json" ||
			strings.Contains(r.Header.Get("Accept"), "application/json") {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
			enc := json.NewEncoder(w)
			enc.SetIndent("", "  ")
			_ = enc.Encode(res)
			return
		}

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		switch {
		case in && out:
			fmt.Fprintf(w, "%s is BLOCKED (inbound + outbound)\n", ip)
		case in:
			fmt.Fprintf(w, "%s is BLOCKED (inbound)\n", ip)
		case out:
			fmt.Fprintf(w, "%s is BLOCKED (outbound)\n", ip)
		default:
			fmt.Fprintf(w, "%s is allowed\n", ip)
		}
		var parts []string
		if res.Geo.City != "" {
			parts = append(parts, res.Geo.City)
		}
		if res.Geo.Region != "" {
			parts = append(parts, res.Geo.Region)
		}
		if res.Geo.Country != "" {
			parts = append(parts, fmt.Sprintf("%s (%s)", res.Geo.Country, res.Geo.CountryISO))
		}
		if len(parts) > 0 {
			fmt.Fprintf(w, "  Location: %s\n", strings.Join(parts, ", "))
		}
		if res.Geo.ASN != 0 {
			fmt.Fprintf(w, "  ASN:      AS%d %s\n", res.Geo.ASN, res.Geo.ASNOrg)
		}
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /check", handle)
	mux.HandleFunc("GET /{$}", handle)

	srv := &http.Server{
		Addr:        bind,
		Handler:     mux,
		BaseContext: func(_ net.Listener) context.Context { return ctx },
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("listening on %s", bind)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
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
