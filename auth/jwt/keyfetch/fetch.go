// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package keyfetch

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// Error sentinels for fetch operations.
var (
	// ErrFetchFailed indicates a network or parsing failure during a JWKS fetch.
	ErrFetchFailed = errors.New("fetch failed")

	// ErrUnexpectedStatus indicates the server returned a non-200 status code.
	ErrUnexpectedStatus = fmt.Errorf("%w: unexpected status", ErrFetchFailed)
)

// maxResponseBody is the maximum JWKS response body size (1 MiB).
// A realistic JWKS with dozens of keys is well under 100 KiB.
const maxResponseBody = 1 << 20

// defaultClient is used when no client is provided.
var defaultClient = &http.Client{Timeout: 30 * time.Second}

// Cacheable holds the response body and HTTP cache metadata from a [Fetch] call.
//
// MaxAge is the effective remaining TTL: the server's Cache-Control max-age
// minus the Age header (which reflects how long the response sat in
// intermediary caches). It is zero when no usable max-age is present.
//
// ETag and LastModified can be sent back on subsequent requests
// (via If-None-Match / If-Modified-Since) to avoid re-downloading
// unchanged content.
type Cacheable struct {
	Data         []byte
	MaxAge       time.Duration // effective TTL (max-age minus Age)
	ETag         string        // opaque validator for conditional re-fetch
	LastModified string        // date-based validator for conditional re-fetch
}

// Fetch retrieves raw bytes from a URL using a default HTTP client (30s timeout).
//
// Use this to fetch key material in any format (JWKS, PEM, DER) from a remote
// endpoint. For the common case of fetching and parsing a JWKS document,
// prefer [FetchURL].
//
// The response body is limited to 1 MiB.
func Fetch(ctx context.Context, url string) (*Cacheable, error) {
	return fetchRaw(ctx, url, nil)
}

// fetchRaw retrieves raw bytes from a URL using the given HTTP client.
// If client is nil, a default client with a 30s timeout is used.
func fetchRaw(ctx context.Context, url string, client *http.Client) (*Cacheable, error) {
	resp, err := doGET(ctx, url, client)
	if err != nil {
		return nil, fmt.Errorf("fetch %q: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, fmt.Errorf("fetch %q: read body: %w: %w", url, ErrFetchFailed, err)
	}

	maxAge := parseCacheControlMaxAge(resp.Header.Get("Cache-Control"))
	if age := parseAge(resp.Header.Get("Age")); age > 0 && maxAge > age {
		maxAge -= age
	} else if age > 0 {
		maxAge = 0
	}

	return &Cacheable{
		Data:         body,
		MaxAge:       maxAge,
		ETag:         resp.Header.Get("ETag"),
		LastModified: resp.Header.Get("Last-Modified"),
	}, nil
}

// FetchURL retrieves and parses a JWKS document from the given JWKS endpoint URL.
//
// It returns the parsed keys and the Cache-Control max-age from the response
// headers (0 if the header is absent or unparseable). Callers that implement
// their own caching (e.g. [KeyFetcher]) can use the returned duration to
// respect the server's preferred TTL.
//
// The response body is limited to 1 MiB. client is the HTTP client to use;
// if nil, a default client with a 30s timeout is used.
func FetchURL(ctx context.Context, jwksURL string, client *http.Client) ([]jwt.PublicKey, time.Duration, error) {
	c, err := fetchRaw(ctx, jwksURL, client)
	if err != nil {
		return nil, 0, err
	}
	var jwks jwt.JWKs
	if err := json.Unmarshal(c.Data, &jwks); err != nil {
		return nil, 0, fmt.Errorf("parse JWKS: %w: %w", ErrFetchFailed, err)
	}
	return jwks.Keys, c.MaxAge, nil
}

// parseCacheControlMaxAge extracts the max-age value from a Cache-Control header.
// Returns 0 if the header is absent or does not contain a valid max-age directive.
func parseCacheControlMaxAge(header string) time.Duration {
	for part := range strings.SplitSeq(header, ",") {
		part = strings.TrimSpace(part)
		if val, ok := strings.CutPrefix(part, "max-age="); ok {
			n, err := strconv.Atoi(val)
			if err == nil && n > 0 {
				return time.Duration(n) * time.Second
			}
		}
	}
	return 0
}

// parseAge extracts the Age header value as a Duration.
// Returns 0 if the header is absent or unparseable.
func parseAge(header string) time.Duration {
	if header == "" {
		return 0
	}
	n, err := strconv.Atoi(strings.TrimSpace(header))
	if err != nil || n <= 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// FetchOIDC fetches JWKS via OIDC discovery from the given base URL.
//
// It fetches {baseURL}/.well-known/openid-configuration, reads the jwks_uri
// field, then fetches and parses the JWKS from that URI.
//
// client is used for all HTTP requests; if nil, a default 30s-timeout client is used.
func FetchOIDC(ctx context.Context, baseURL string, client *http.Client) ([]jwt.PublicKey, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"
	jwksURI, err := fetchDiscoveryURI(ctx, discoveryURL, client)
	if err != nil {
		return nil, err
	}
	keys, _, err := FetchURL(ctx, jwksURI, client)
	return keys, err
}

// FetchOAuth2 fetches JWKS via OAuth 2.0 authorization server metadata from the
// given base URL.
//
// https://www.rfc-editor.org/rfc/rfc8414.html
//
// It fetches {baseURL}/.well-known/oauth-authorization-server, reads the
// jwks_uri field, then fetches and parses the JWKS from that URI.
//
// client is used for all HTTP requests; if nil, a default 30s-timeout client is used.
func FetchOAuth2(ctx context.Context, baseURL string, client *http.Client) ([]jwt.PublicKey, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server"
	jwksURI, err := fetchDiscoveryURI(ctx, discoveryURL, client)
	if err != nil {
		return nil, err
	}
	keys, _, err := FetchURL(ctx, jwksURI, client)
	return keys, err
}

// fetchDiscoveryURI fetches a discovery document and returns the validated
// jwks_uri from it. The URI is required to use HTTPS to prevent SSRF via a
// malicious discovery document pointing at an internal endpoint.
func fetchDiscoveryURI(ctx context.Context, discoveryURL string, client *http.Client) (string, error) {
	resp, err := doGET(ctx, discoveryURL, client)
	if err != nil {
		return "", fmt.Errorf("fetch discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	var doc struct {
		JWKsURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&doc); err != nil {
		return "", fmt.Errorf("parse discovery doc: %w: %w", ErrFetchFailed, err)
	}
	if doc.JWKsURI == "" {
		return "", fmt.Errorf("discovery doc missing jwks_uri: %w", ErrFetchFailed)
	}
	if !strings.HasPrefix(doc.JWKsURI, "https://") {
		return "", fmt.Errorf("jwks_uri must be https, got %q: %w", doc.JWKsURI, ErrFetchFailed)
	}
	return doc.JWKsURI, nil
}

// doGET performs an HTTP GET request and returns the response. It handles
// nil client defaults and status code checking. Callers must close resp.Body.
func doGET(ctx context.Context, url string, client *http.Client) (*http.Response, error) {
	if client == nil {
		client = defaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("status %d: %w", resp.StatusCode, ErrUnexpectedStatus)
	}
	return resp, nil
}
