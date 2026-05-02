package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
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
	Allowlisted     bool       `json:"allowlisted,omitzero"`
	Geo             geoip.Info `json:"geo,omitzero"`
}

// lookup builds a Result for ip against the currently loaded blocklists
// and GeoIP databases.
func (c *IPCheck) lookup(ip string) Result {
	res := Result{IP: ip, Geo: c.geo.Value().Lookup(ip)}
	addr, err := netip.ParseAddr(ip)
	if err != nil {
		res.Blocked = true
		res.BlockedInbound = true
		res.BlockedOutbound = true
		return res
	}
	if c.whitelist != nil && c.whitelist.Value().ContainsAddr(addr) {
		res.Allowlisted = true
		return res
	}
	res.BlockedInbound = c.inbound.Value().ContainsAddr(addr)
	res.BlockedOutbound = c.outbound.Value().ContainsAddr(addr)
	res.Blocked = res.BlockedInbound || res.BlockedOutbound
	return res
}

// writeText renders res as human-readable plain text.
func (c *IPCheck) writeText(w io.Writer, res Result) {
	switch {
	case res.Allowlisted:
		fmt.Fprintf(w, "%s is ALLOWED (whitelist)\n", res.IP)
	case res.BlockedInbound && res.BlockedOutbound:
		fmt.Fprintf(w, "%s is BLOCKED (inbound + outbound)\n", res.IP)
	case res.BlockedInbound:
		fmt.Fprintf(w, "%s is BLOCKED (inbound)\n", res.IP)
	case res.BlockedOutbound:
		fmt.Fprintf(w, "%s is BLOCKED (outbound)\n", res.IP)
	default:
		fmt.Fprintf(w, "%s is allowed\n", res.IP)
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

func (c *IPCheck) handle(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if ip == "" {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			first, _, _ := strings.Cut(xff, ",")
			ip = strings.TrimSpace(first)
		} else if host, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
			ip = host
		} else {
			ip = r.RemoteAddr
		}
	}
	res := c.lookup(ip)

	if r.URL.Query().Get("format") == "json" ||
		strings.Contains(r.Header.Get("Accept"), "application/json") {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return
	}

	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	c.writeText(w, res)
}

type dsStatus struct {
	Loaded   bool      `json:"loaded"`
	Size     int       `json:"size,omitzero"`
	LoadedAt time.Time `json:"loaded_at,omitzero"`
}

// healthz reports per-dataset load state and an overall ready flag.
// Returns 200 when all required sets (inbound, outbound, geoip) are
// loaded, 503 while any are still empty.
func (c *IPCheck) healthz(w http.ResponseWriter, _ *http.Request) {
	cohortStatus := func(v *dataset.View[ipcohort.Cohort]) dsStatus {
		s := dsStatus{LoadedAt: v.LoadedAt()}
		if cur := v.Value(); cur != nil {
			s.Loaded, s.Size = true, cur.Size()
		}
		return s
	}

	datasets := map[string]dsStatus{
		"inbound":  cohortStatus(c.inbound),
		"outbound": cohortStatus(c.outbound),
		"geoip": {
			Loaded:   c.geo.Value() != nil,
			LoadedAt: c.geo.LoadedAt(),
		},
	}
	if c.whitelist != nil {
		datasets["whitelist"] = cohortStatus(c.whitelist)
	}

	ready := datasets["inbound"].Loaded && datasets["outbound"].Loaded && datasets["geoip"].Loaded
	resp := struct {
		Ready    bool                `json:"ready"`
		Version  string              `json:"version"`
		Datasets map[string]dsStatus `json:"datasets"`
	}{ready, version, datasets}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	_ = enc.Encode(resp)
}

func (c *IPCheck) serve(ctx context.Context) error {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /check", c.handle)
	mux.HandleFunc("GET /healthz", c.healthz)
	mux.HandleFunc("GET /{$}", c.handle)

	srv := &http.Server{
		Addr:              c.Bind,
		Handler:           mux,
		BaseContext:       func(_ net.Listener) context.Context { return ctx },
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      15 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    1 << 16, // 64KB
	}
	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutCtx)
	}()

	log.Printf("listening on %s", c.Bind)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}
