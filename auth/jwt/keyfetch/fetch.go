// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
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
	// ErrFetchFailed indicates a network, HTTP, or parsing failure during
	// a JWKS fetch. The wrapped message includes details (status code,
	// network error, parse error, etc).
	ErrFetchFailed = errors.New("fetch failed")

	// ErrKeysExpired indicates the cached keys are past their hard expiry.
	// Returned alongside expired keys when RefreshTimeout fires before the
	// refresh completes. Use [errors.Is] to check.
	ErrKeysExpired = errors.New("cached keys expired")

	// ErrEmptyKeySet indicates the JWKS document contains no keys.
	ErrEmptyKeySet = errors.New("empty key set")
)

// maxResponseBody is the maximum JWKS response body size (1 MiB).
// A realistic JWKS with dozens of keys is well under 100 KiB.
const maxResponseBody = 1 << 20

// Default cache policy values, used when the corresponding [KeyFetcher]
// field is zero.
const (
	defaultMinTTL = 1 * time.Minute  // floor - server values below this are raised
	defaultMaxTTL = 24 * time.Hour   // ceiling - server values above this are clamped
	defaultTTL    = 15 * time.Minute // used when no cache headers are present
)

// defaultTimeout is the timeout used when no HTTP client is provided.
const defaultTimeout = 30 * time.Second

// asset holds the response body and computed cache timing from a fetch.
type asset struct {
	data         []byte
	expiry       time.Time // hard expiry - do not use after this time
	stale        time.Time // background refresh should start at this time
	etag         string    // opaque validator for conditional re-fetch
	lastModified string    // date-based validator for conditional re-fetch
}

// fetchRaw retrieves raw bytes from a URL using the given HTTP client.
// If prev is non-nil, conditional request headers (If-None-Match,
// If-Modified-Since) are sent; a 304 response refreshes the cache
// timing on prev and returns it without re-downloading the body.
// If client is nil, a default client with a 30s timeout is used.
//
// The returned *http.Response has its Body consumed and closed; headers
// remain accessible.
func fetchRaw(ctx context.Context, url string, client *http.Client, p cachePolicy, prev *asset) (*asset, *http.Response, error) {
	resp, err := doGET(ctx, url, client, prev)
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %q: %w", url, err)
	}
	defer func() { _ = resp.Body.Close() }()

	now := time.Now()

	// 304 Not Modified - reuse previous body with refreshed cache timing.
	if resp.StatusCode == http.StatusNotModified && prev != nil {
		expiry, stale := cacheTimings(now, resp, p)
		etag := resp.Header.Get("ETag")
		if etag == "" {
			etag = prev.etag
		}
		lastMod := resp.Header.Get("Last-Modified")
		if lastMod == "" {
			lastMod = prev.lastModified
		}
		return &asset{
			data:         prev.data,
			expiry:       expiry,
			stale:        stale,
			etag:         etag,
			lastModified: lastMod,
		}, resp, nil
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return nil, nil, fmt.Errorf("fetch %q: read body: %w: %w", url, ErrFetchFailed, err)
	}
	if len(body) > maxResponseBody {
		return nil, nil, fmt.Errorf("fetch %q: response exceeds %d byte limit: %w", url, maxResponseBody, ErrFetchFailed)
	}

	expiry, stale := cacheTimings(now, resp, p)

	return &asset{
		data:         body,
		expiry:       expiry,
		stale:        stale,
		etag:         resp.Header.Get("ETag"),
		lastModified: resp.Header.Get("Last-Modified"),
	}, resp, nil
}

// cachePolicy holds resolved cache tuning parameters.
type cachePolicy struct {
	minTTL     time.Duration
	maxTTL     time.Duration
	defaultTTL time.Duration
}

// defaultPolicy returns a cachePolicy using the package defaults.
func defaultPolicy() cachePolicy {
	return cachePolicy{
		minTTL:     defaultMinTTL,
		maxTTL:     defaultMaxTTL,
		defaultTTL: defaultTTL,
	}
}

// cacheTimings computes expiry and stale times from the response headers.
// Stale time is always 3/4 of the TTL.
//
// Policy:
//   - No usable max-age      => defaultTTL (15m), stale at 3/4
//   - max-age < minTTL (1m)  => minTTL*2 expiry, minTTL stale
//   - max-age > maxTTL (24h) => clamped to maxTTL, stale at 3/4
//   - Otherwise              => server value, stale at 3/4
func cacheTimings(now time.Time, resp *http.Response, p cachePolicy) (expiry, stale time.Time) {
	serverTTL := parseCacheControlMaxAge(resp.Header.Get("Cache-Control"))
	if age := parseAge(resp.Header.Get("Age")); age > 0 {
		serverTTL -= age
	}

	var ttl time.Duration
	switch {
	case serverTTL <= 0:
		// No cache headers or max-age=0 or Age consumed it all
		ttl = p.defaultTTL
	case serverTTL < p.minTTL:
		// Server says cache briefly - use floor
		return now.Add(p.minTTL * 2), now.Add(p.minTTL)
	case serverTTL > p.maxTTL:
		ttl = p.maxTTL
	default:
		ttl = serverTTL
	}

	return now.Add(ttl), now.Add(ttl * 3 / 4)
}

// FetchURL retrieves and parses a JWKS document from the given JWKS endpoint URL.
//
// The response body is limited to 1 MiB. If client is nil, a default client
// with a 30s timeout is used.
//
// The returned [*http.Response] has its Body already consumed and closed.
// Headers such as ETag, Last-Modified, and Cache-Control remain accessible
// and are used internally by [KeyFetcher] for cache management.
func FetchURL(ctx context.Context, jwksURL string, client *http.Client) ([]jwt.PublicKey, *http.Response, error) {
	a, resp, err := fetchRaw(ctx, jwksURL, client, defaultPolicy(), nil)
	if err != nil {
		return nil, nil, err
	}
	keys, err := parseJWKS(a.data)
	if err != nil {
		return nil, nil, err
	}
	return keys, resp, nil
}

// fetchJWKS fetches and parses a JWKS document, returning the asset for
// cache timing and the parsed keys. prev is passed through to fetchRaw
// for conditional requests.
func fetchJWKS(ctx context.Context, jwksURL string, client *http.Client, p cachePolicy, prev *asset) (*asset, []jwt.PublicKey, error) {
	a, _, err := fetchRaw(ctx, jwksURL, client, p, prev)
	if err != nil {
		return nil, nil, err
	}
	keys, err := parseJWKS(a.data)
	if err != nil {
		return nil, nil, err
	}
	return a, keys, nil
}

// parseJWKS unmarshals a JWKS document into public keys.
// Returns [ErrEmptyKeySet] if the key set is empty.
func parseJWKS(data []byte) ([]jwt.PublicKey, error) {
	var jwks jwt.WellKnownJWKs
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS: %w: %w", ErrFetchFailed, err)
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("parse JWKS: %w", ErrEmptyKeySet)
	}
	return jwks.Keys, nil
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
func FetchOIDC(ctx context.Context, baseURL string, client *http.Client) ([]jwt.PublicKey, *http.Response, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"
	jwksURI, err := fetchDiscoveryURI(ctx, discoveryURL, client)
	if err != nil {
		return nil, nil, err
	}
	return FetchURL(ctx, jwksURI, client)
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
func FetchOAuth2(ctx context.Context, baseURL string, client *http.Client) ([]jwt.PublicKey, *http.Response, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server"
	jwksURI, err := fetchDiscoveryURI(ctx, discoveryURL, client)
	if err != nil {
		return nil, nil, err
	}
	return FetchURL(ctx, jwksURI, client)
}

// fetchDiscoveryURI fetches a discovery document and returns the validated
// jwks_uri from it. The URI is required to use HTTPS to prevent SSRF via a
// malicious discovery document pointing at an internal endpoint.
func fetchDiscoveryURI(ctx context.Context, discoveryURL string, client *http.Client) (string, error) {
	resp, err := doGET(ctx, discoveryURL, client, nil)
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

// doGET performs an HTTP GET request and returns the response. It follows
// redirects (Go's default of up to 10), handles nil client defaults, and
// checks the final status code. If prev is non-nil, conditional request
// headers are sent and a 304 response is allowed. Callers must close
// resp.Body.
func doGET(ctx context.Context, url string, client *http.Client, prev *asset) (*http.Response, error) {
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	if prev != nil {
		if prev.etag != "" {
			req.Header.Set("If-None-Match", prev.etag)
		}
		if prev.lastModified != "" {
			req.Header.Set("If-Modified-Since", prev.lastModified)
		}
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFetchFailed, err)
	}
	if resp.StatusCode == http.StatusNotModified && prev != nil {
		return resp, nil
	}
	if resp.StatusCode != http.StatusOK {
		_ = resp.Body.Close()
		return nil, fmt.Errorf("status %d: %w", resp.StatusCode, ErrFetchFailed)
	}
	return resp, nil
}
