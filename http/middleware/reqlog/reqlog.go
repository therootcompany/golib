// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) has dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// SPDX-License-Identifier: CC0-1.0

package reqlog

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/therootcompany/golib/3p/ulid/v2"
)

// reqlog gives every request a request ID (a ULID) and writes exactly one
// structured slog record per request when it completes.
//
// Ordering: realip.Trust → RequestID → Logger → Recover. The logger writes
// its record in a defer, so a panic unwinds through it after Recover has
// written the 500 - the single record still captures status and duration.
//
// There is no request-time record and no response-time record: one record,
// written when the request is done. Long-running requests are observed by
// the absence of a record, not by a second one.

const requestIDHeader = "X-Request-Id"

// requestIDHeaderMax caps any upstream-provided ID. Tokens longer than this
// are treated as garbage and replaced.
const requestIDHeaderMax = 64

// requestIDKey holds the request ID for the duration of the request.
type requestIDKey struct{}

// RequestID assigns every request a request ID: it reuses the TLS router's
// X-Request-Id when the upstream value is sane (non-empty, no control
// characters, at most 64 characters), and generates a ULID otherwise. The
// ID is stored in the request context and echoed in the response header.
//
// TODO: decide whether to adopt W3C traceparent for cross-service tracing;
// the reuse rule may need to honour an existing trace ID.
func RequestID() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := strings.TrimSpace(r.Header.Get(requestIDHeader))
			if id == "" || len(id) > requestIDHeaderMax || hasControlChars(id) {
				id = ulid.Make().String()
			}
			r = r.WithContext(context.WithValue(r.Context(), requestIDKey{}, id))
			w.Header().Set(requestIDHeader, id)
			next.ServeHTTP(w, r)
		})
	}
}

// RequestIDFromContext returns the request ID, or "" when RequestID has not
// run. Handlers, error paths, and limiters read the ID here.
func RequestIDFromContext(r *http.Request) string {
	id, _ := r.Context().Value(requestIDKey{}).(string)
	return id
}

func hasControlChars(s string) bool {
	for _, ch := range s {
		if ch < ' ' || ch == 127 {
			return true
		}
	}
	return false
}

// statusRecorder captures the status code written by the handler, so the
// logger can report it. A handler that never calls WriteHeader implicitly
// returned 200.
type statusRecorder struct {
	http.ResponseWriter
	status int
}

func (s *statusRecorder) WriteHeader(code int) {
	if s.status == 0 {
		s.status = code
	}
	s.ResponseWriter.WriteHeader(code)
}

func (s *statusRecorder) Flush() {
	if f, ok := s.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// Logger writes one slog record per completed request with the fleet schema:
// request_id, method, path, query, status, duration_ms, remote, proto, ua,
// content_length. Headers are never logged; Authorization and Cookie are
// never anywhere near the record.
//
// remote is whatever RemoteAddr holds at this point - run realip.Trust
// before the logger so it is the client rather than the router. The proxy
// address (realip.PeerIP) is intentionally not part of this schema: reqlog
// does not depend on realip, and services that need it can add it with a
// slog attribute or a small wrapper middleware.
func Logger(logger *slog.Logger, red Redaction) func(http.Handler) http.Handler {
	if logger == nil {
		logger = slog.Default()
	}
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			rec := &statusRecorder{ResponseWriter: w}
			start := time.Now()

			defer func() {
				status := rec.status
				if status == 0 {
					status = http.StatusOK
				}
				logger.Info("request",
					"request_id", RequestIDFromContext(r),
					"method", r.Method,
					"path", sanitizePath(r.URL.Path, red),
					"query", sanitizeQuery(r.URL.RawQuery, red),
					"status", status,
					"duration_ms", time.Since(start).Milliseconds(),
					"remote", r.RemoteAddr,
					"proto", r.Proto,
					"ua", truncate(r.Header.Get("User-Agent"), 200),
					"content_length", r.ContentLength,
				)
			}()

			next.ServeHTTP(rec, r)
		})
	}
}

func truncate(s string, max int) string {
	if len(s) > max {
		return s[:max]
	}
	return s
}
