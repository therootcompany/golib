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
	"net/http"
	"strings"
	"time"
)

// FetchURL retrieves and parses a JWKS document from the given JWKS endpoint URL.
//
// ctx is used for the HTTP request timeout and cancellation.
func FetchURL(ctx context.Context, jwksURL string) ([]Key, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, jwksURL, nil)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("fetch JWKS: unexpected status %d", resp.StatusCode)
	}
	return Decode(resp.Body)
}

// FetchOIDC fetches JWKS via OIDC discovery from the given base URL.
//
// It fetches {baseURL}/.well-known/openid-configuration and reads the jwks_uri field.
func FetchOIDC(ctx context.Context, baseURL string) ([]Key, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"
	keys, _, err := fetchFromDiscovery(ctx, discoveryURL)
	return keys, err
}

// FetchOAuth2 fetches JWKS via OAuth 2.0 authorization server metadata (RFC 8414)
// from the given base URL.
//
// It fetches {baseURL}/.well-known/oauth-authorization-server and reads the jwks_uri field.
func FetchOAuth2(ctx context.Context, baseURL string) ([]Key, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server"
	keys, _, err := fetchFromDiscovery(ctx, discoveryURL)
	return keys, err
}

// fetchFromDiscovery fetches a discovery document from discoveryURL, then
// fetches the JWKS from the jwks_uri field. Returns the keys and the issuer
// URL from the discovery document's "issuer" field.
func fetchFromDiscovery(ctx context.Context, discoveryURL string) ([]Key, string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return nil, "", fmt.Errorf("fetch discovery: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("fetch discovery: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, "", fmt.Errorf("fetch discovery: unexpected status %d", resp.StatusCode)
	}

	var doc struct {
		Issuer  string `json:"issuer"`
		JWKsURI string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&doc); err != nil {
		return nil, "", fmt.Errorf("parse discovery doc: %w", err)
	}
	if doc.JWKsURI == "" {
		return nil, "", fmt.Errorf("discovery doc missing jwks_uri field")
	}

	keys, err := FetchURL(ctx, doc.JWKsURI)
	if err != nil {
		return nil, "", err
	}
	return keys, doc.Issuer, nil
}
