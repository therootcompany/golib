// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwk

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt/jose"
)

// maxResponseBody is the maximum JWKS response body size (1 MiB).
// A realistic JWKS with dozens of keys is well under 100 KiB.
const maxResponseBody = 1 << 20

// defaultClient is used when no client is provided.
var defaultClient = &http.Client{Timeout: 30 * time.Second}

// FetchURL retrieves and parses a JWKS document from the given JWKS endpoint URL.
//
// It returns the parsed keys and the Cache-Control max-age from the response
// headers (0 if the header is absent or unparseable). Callers that implement
// their own caching (e.g. [jwt.KeyFetcher]) can use the returned duration to
// respect the server's preferred TTL.
//
// The response body is limited to [maxResponseBody] bytes. client is the HTTP
// client to use; if nil, a default client with a 30s timeout is used.
func FetchURL(ctx context.Context, jwksURL string, client *http.Client) ([]PublicKey, time.Duration, error) {
	if client == nil {
		client = defaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch JWKS: %w: %w", jose.ErrFetchFailed, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("fetch JWKS: %w: %w", jose.ErrFetchFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("fetch JWKS: status %d: %w", resp.StatusCode, jose.ErrUnexpectedStatus)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, 0, fmt.Errorf("fetch JWKS: read body: %w: %w", jose.ErrFetchFailed, err)
	}
	var jwks JWKs
	if err := json.Unmarshal(body, &jwks); err != nil {
		return nil, 0, fmt.Errorf("parse JWKS: %w: %w", jose.ErrFetchFailed, err)
	}
	return jwks.Keys, parseCacheControlMaxAge(resp.Header.Get("Cache-Control")), nil
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

// FetchOIDC fetches JWKS via OIDC discovery from the given base URL.
//
// It fetches {baseURL}/.well-known/openid-configuration and reads the jwks_uri field.
// client is used for all HTTP requests; if nil, a default 30s-timeout client is used.
func FetchOIDC(ctx context.Context, baseURL string, client *http.Client) ([]PublicKey, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"
	keys, _, err := fetchFromDiscovery(ctx, discoveryURL, client)
	return keys, err
}

// FetchOAuth2 fetches JWKS via OAuth 2.0 authorization server metadata from the
// given base URL.
//
// https://www.rfc-editor.org/rfc/rfc8414.html
//
// It fetches {baseURL}/.well-known/oauth-authorization-server and reads the jwks_uri field.
// client is used for all HTTP requests; if nil, a default 30s-timeout client is used.
func FetchOAuth2(ctx context.Context, baseURL string, client *http.Client) ([]PublicKey, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server"
	keys, _, err := fetchFromDiscovery(ctx, discoveryURL, client)
	return keys, err
}

// fetchFromDiscovery fetches a discovery document from discoveryURL, then
// fetches the JWKS from the jwks_uri field. Returns the keys and the issuer
// URL from the discovery document's "issuer" field.
// TODO this should return the URL, not the keys
func fetchFromDiscovery(ctx context.Context, discoveryURL string, client *http.Client) ([]PublicKey, string, error) {
	if client == nil {
		client = defaultClient
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("fetch discovery: %w: %w", jose.ErrFetchFailed, err)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch discovery: %w: %w", jose.ErrFetchFailed, err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("fetch discovery: status %d: %w", resp.StatusCode, jose.ErrUnexpectedStatus)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKsURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, maxResponseBody)).Decode(&doc); err != nil {
		return nil, "", fmt.Errorf("parse discovery doc: %w: %w", jose.ErrFetchFailed, err)
	}
	if doc.JWKsURI == "" {
		return nil, "", fmt.Errorf("discovery doc missing jwks_uri: %w", jose.ErrFetchFailed)
	}

	// TODO lift this up
	keys, _, err := FetchURL(ctx, doc.JWKsURI, client)
	if err != nil {
		return nil, "", err
	}
	return keys, doc.Issuer, nil
}
