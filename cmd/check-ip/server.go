package main

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strings"
	"time"
)

const shutdownTimeout = 5 * time.Second

// serve runs the HTTP server until ctx is cancelled, shutting down gracefully.
//
//	GET /         checks the request's client IP
//	GET /check    same, plus ?ip= overrides
//
// Format is chosen per request via ?format=, then Accept: application/json.
func serve(ctx context.Context, cfg Config, checker *Checker) error {
	handle := func(w http.ResponseWriter, r *http.Request, ip string) {
		format := requestFormat(r)
		if format == FormatJSON {
			w.Header().Set("Content-Type", "application/json; charset=utf-8")
		} else {
			w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		}
		checker.Check(ip).Report(w, format)
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
		Addr:    cfg.Serve,
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

	fmt.Fprintf(os.Stderr, "listening on %s\n", cfg.Serve)
	if err := srv.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

// requestFormat picks a response format from ?format=, then Accept header.
func requestFormat(r *http.Request) Format {
	if q := r.URL.Query().Get("format"); q != "" {
		if f, err := parseFormat(q); err == nil {
			return f
		}
	}
	if strings.Contains(r.Header.Get("Accept"), "application/json") {
		return FormatJSON
	}
	return FormatPretty
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
