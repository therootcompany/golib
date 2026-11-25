// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) has dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// SPDX-License-Identifier: CC0-1.0

package reqlog

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/therootcompany/golib/3p/ulid/v2"
)

func TestRequestIDGeneratesULID(t *testing.T) {
	req := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	rec := httptest.NewRecorder()

	var got string
	handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got = RequestIDFromContext(r)
		w.Header().Set("X-Seen-Id", got)
	}))
	handler.ServeHTTP(rec, req)

	if got == "" {
		t.Fatal("no request ID in context")
	}
	if _, err := ulid.Parse(got); err != nil {
		t.Errorf("generated request ID %q is not a ULID: %v", got, err)
	}
	if rec.Header().Get("X-Request-Id") != got {
		t.Errorf("response header X-Request-Id = %q, want %q", rec.Header().Get("X-Request-Id"), got)
	}
}

func TestRequestIDReusesUpstreamID(t *testing.T) {
	cases := []struct {
		in   string
		want string // "" means the middleware must replace it with a fresh ULID
	}{
		{"01HZYEXAMPLE000000000000AA", "01HZYEXAMPLE000000000000AA"},
		{"a-real-token-from-the-router", "a-real-token-from-the-router"},
		{"", ""},                      // absent: generate
		{strings.Repeat("x", 65), ""}, // too long: replace
		{"bad\u0001token", ""},        // control characters: replace
	}

	for _, c := range cases {
		req := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
		if c.in != "" {
			req.Header.Set("X-Request-Id", c.in)
		}
		rec := httptest.NewRecorder()

		var got string
		handler := RequestID()(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got = RequestIDFromContext(r)
		}))
		handler.ServeHTTP(rec, req)

		if c.want != "" && got != c.want {
			t.Errorf("upstream ID %q: got %q, want %q", c.in, got, c.want)
		}
		if c.want == "" {
			if _, err := ulid.Parse(got); err != nil {
				t.Errorf("upstream ID %q rejected but replacement %q is not a ULID: %v", c.in, got, err)
			}
		}
	}
}

func TestLoggerWritesOneRecordWithSchema(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))

	red := Redaction{
		QueryDeny:   []string{"access_token"},
		PathSecrets: []string{"/rooms/*"},
	}

	handler := Logger(logger, red)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusTeapot)
		w.Write([]byte("done"))
	}))

	req := httptest.NewRequest(http.MethodGet, "/rooms/abc123?access_token=secret", nil)
	req.Header.Set("User-Agent", "curl/8.5")
	req.Header.Set("Authorization", "Bearer supersecrettoken")
	handler.ServeHTTP(httptest.NewRecorder(), req)

	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("logger output is not one JSON record: %v", err)
	}

	for _, key := range []string{"request_id", "method", "path", "query", "status", "duration_ms", "remote", "proto", "ua", "content_length"} {
		if _, ok := record[key]; !ok {
			t.Errorf("log record missing %q", key)
		}
	}
	status, _ := record["status"].(float64)
	if int(status) != http.StatusTeapot {
		t.Errorf("status = %v, want %d", record["status"], http.StatusTeapot)
	}
	if record["path"] != "/rooms/**c123" {
		t.Errorf("path = %v, want the secret segment masked, not deleted", record["path"])
	}
	if record["query"] != "access_token=**cret" {
		t.Errorf("query = %v, want the deny-listed value masked", record["query"])
	}
	if strings.Contains(out.String(), "supersecrettoken") {
		t.Error("log record leaked an Authorization header value")
	}
}

func TestLoggerRecordsDuration(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))

	handler := Logger(logger, Redaction{})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(20 * time.Millisecond)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/thing", nil))

	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("logger output is not one JSON record: %v", err)
	}
	duration, _ := record["duration_ms"].(float64)
	if duration < 20 {
		t.Errorf("duration_ms = %v, want at least 20", duration)
	}
}

func TestSanitizeQueryMasksDenyListedValues(t *testing.T) {
	red := Redaction{QueryDeny: []string{"access_token", "id_token", "code", "sig"}}
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"q=hello&limit=5", "q=hello&limit=5"},
		{"access_token=supersecret", "access_token=*******cret"},
		{"access_token=secret", "access_token=**cret"},
		{"access_token=abcd", "access_token=****"}, // as short as the keep, fully masked
		{"access_token=x", "access_token=*"},
		{"access_token", "access_token"}, // no value, nothing to mask
		{"code=a%2Fb%2Fc%2Fd", "code=*********%2Fd"},
		{"id_token=deadbeef&q=1", "id_token=****beef&q=1"},
		{"access_token=hello1&access_token=hello2", "access_token=**llo1&access_token=**llo2"},
	}
	for _, c := range cases {
		if got := sanitizeQuery(c.in, red); got != c.want {
			t.Errorf("sanitizeQuery(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizeQueryMaskDelete(t *testing.T) {
	red := Redaction{QueryDeny: []string{"access_token"}, Mask: MaskDelete}
	got := sanitizeQuery("access_token=supersecret&q=1", red)
	if got != "access_token=&q=1" {
		t.Errorf("sanitizeQuery = %q, want %q", got, "access_token=&q=1")
	}
}

func TestSanitizePathMasksSecretSegments(t *testing.T) {
	red := Redaction{PathSecrets: []string{"/rooms/*", "/auth/{email}"}}
	cases := []struct {
		in   string
		want string
	}{
		{"/rooms/abc123", "/rooms/**c123"},
		{"/rooms/abc123/messages", "/rooms/**c123/messages"},
		{"/auth/aj@example.com", "/auth/**********.com"},
		{"/api/thing", "/api/thing"},
		{"/rooms/", "/rooms/"}, // no secret segment present
		{"/auth/", "/auth/"},
	}
	for _, c := range cases {
		if got := sanitizePath(c.in, red); got != c.want {
			t.Errorf("sanitizePath(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSanitizePathMaskDelete(t *testing.T) {
	red := Redaction{PathSecrets: []string{"/rooms/*"}, Mask: MaskDelete}
	if got := sanitizePath("/rooms/abc123/messages", red); got != "/rooms//messages" {
		t.Errorf("sanitizePath = %q, want the segment emptied", got)
	}
}

func TestNoRedactionIsTheIdentity(t *testing.T) {
	red := Redaction{}
	if got := sanitizeQuery("access_token=supersecret", red); got != "access_token=supersecret" {
		t.Errorf("empty QueryDeny modified the query: %q", got)
	}
	if got := sanitizePath("/rooms/abc123", red); got != "/rooms/abc123" {
		t.Errorf("empty PathSecrets modified the path: %q", got)
	}
}

func TestWhitelistModeMasksEverythingButTheAllowList(t *testing.T) {
	red := Redaction{
		Mode:       RedactWhitelist,
		QueryAllow: []string{"q", "limit"},
	}
	got := sanitizeQuery("q=hello&access_token=supersecret&id=abc123&page=2", red)
	want := "q=hello&access_token=*******cret&id=**c123&page=*"
	if got != want {
		t.Errorf("sanitizeQuery = %q, want %q", got, want)
	}

	// An empty allow list masks every value - the point of the mode.
	red = Redaction{Mode: RedactWhitelist}
	got = sanitizeQuery("q=hello&id=abc123", red)
	if got != "q=*ello&id=**c123" {
		t.Errorf("empty allow list = %q, want everything masked", got)
	}
}

func TestWhitelistModeKeepRuleOnABlacklistedName(t *testing.T) {
	// The ULID is time-ordered, so its prefix is the half worth keeping.
	red := Redaction{
		Mode:       RedactWhitelist,
		QueryAllow: []string{"q"},
		QueryDeny:  []string{"request_id"},
		Keep:       map[string]Keep{"request_id": {Prefix: 4}},
	}
	got := sanitizeQuery("q=hello&request_id=01HZYEXTRA0000", red)
	want := "q=hello&request_id=01HZ**********"
	if got != want {
		t.Errorf("sanitizeQuery = %q, want %q", got, want)
	}
}

func TestDenyWinsOverAllowInWhitelistMode(t *testing.T) {
	red := Redaction{
		Mode:       RedactWhitelist,
		QueryAllow: []string{"token"},
		QueryDeny:  []string{"token"},
		Keep:       map[string]Keep{"token": {Suffix: 2}},
	}
	got := sanitizeQuery("token=abc12345", red)
	if got != "token=******45" {
		t.Errorf("sanitizeQuery = %q, want the deny rule to win", got)
	}
}

func TestKeepRulesInBlacklistMode(t *testing.T) {
	red := Redaction{
		QueryDeny: []string{"access_token", "trace"},
		Keep: map[string]Keep{
			"access_token": {Prefix: 3}, // head of the token identifies it
			"trace":        {Prefix: 2, Suffix: 3},
		},
	}
	got := sanitizeQuery("access_token=supersecret&trace=supersecret&q=1", red)
	want := "access_token=sup********&trace=su******ret&q=1"
	if got != want {
		t.Errorf("sanitizeQuery = %q, want %q", got, want)
	}
}

func TestKeepRuleCoveringTheWholeValueMasksItEntirely(t *testing.T) {
	red := Redaction{
		QueryDeny: []string{"pin"},
		Keep:      map[string]Keep{"pin": {Prefix: 3, Suffix: 3}},
	}
	if got := sanitizeQuery("pin=abcd", red); got != "pin=****" {
		t.Errorf("sanitizeQuery = %q, want the whole value masked", got)
	}

	red.Keep["pin"] = Keep{Prefix: 99, Suffix: 99} // clamped to the value
	if got := sanitizeQuery("pin=ab", red); got != "pin=**" {
		t.Errorf("sanitizeQuery = %q, want the whole value masked", got)
	}
}

func TestPathKeepRule(t *testing.T) {
	red := Redaction{
		PathSecrets: []string{"/rooms/*"},
		Keep:        map[string]Keep{"/rooms/*": {Prefix: 2}},
	}
	if got := sanitizePath("/rooms/abc123", red); got != "/rooms/ab****" {
		t.Errorf("sanitizePath = %q, want the prefix kept", got)
	}

	red = Redaction{
		PathSecrets: []string{"/auth/{email}"},
		Keep:        map[string]Keep{"/auth/{email}": {Suffix: 5}},
	}
	if got := sanitizePath("/auth/aj@example.com", red); got != "/auth/*********e.com" {
		t.Errorf("sanitizePath = %q, want the suffix kept", got)
	}
}

func TestLoggerWhitelistMode(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))

	red := Redaction{
		Mode:       RedactWhitelist,
		QueryAllow: []string{"q"},
		Keep:       map[string]Keep{"user": {Prefix: 3}},
	}
	handler := Logger(logger, red)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/rooms/abc123?q=1&user=johannes&token=secret", nil))

	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("logger output is not one JSON record: %v", err)
	}
	if record["query"] != "q=1&user=joh*****&token=**cret" {
		t.Errorf("query = %v, want only the allow-listed parameter in full", record["query"])
	}
	if record["path"] != "/rooms/abc123" {
		t.Errorf("path = %v, want it unchanged - PathSecrets is the path policy", record["path"])
	}
}

func TestLoggerCapturesPanicAs500(t *testing.T) {
	var out bytes.Buffer
	logger := slog.New(slog.NewJSONHandler(&out, nil))

	recoverPanics := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				if recover() != nil {
					http.Error(w, "internal server error", http.StatusInternalServerError)
				}
			}()
			next.ServeHTTP(w, r)
		})
	}

	handler := RequestID()(Logger(logger, Redaction{})(recoverPanics(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		panic("boom")
	}))))

	handler.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/thing", nil))

	var record map[string]any
	if err := json.Unmarshal(out.Bytes(), &record); err != nil {
		t.Fatalf("logger output is not one JSON record: %v", err)
	}
	status, _ := record["status"].(float64)
	if int(status) != http.StatusInternalServerError {
		t.Errorf("panic did not produce status 500 in the single record: got %v", record["status"])
	}
}
