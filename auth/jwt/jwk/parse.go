// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwk

import (
	"encoding/json"
	"os"
	"strings"
)

// --- Parse functions (bytes → key) ---

// ParsePublicJWK parses a single JWK JSON object into a [PublicKey].
// KID is auto-computed from the RFC 7638 thumbprint if not present in the JWK.
func ParsePublicJWK(data []byte) (*PublicKey, error) {
	var pk PublicKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, err
	}
	return &pk, nil
}

// ParsePrivateJWK parses a single JWK JSON object with private key material
// into a [PrivateKey]. The "d" field must be present.
// KID is auto-computed from the RFC 7638 thumbprint if not present in the JWK.
func ParsePrivateJWK(data []byte) (*PrivateKey, error) {
	var pk PrivateKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, err
	}
	return &pk, nil
}

// ParsePublicJWKs parses a JWKS document ({"keys": [...]}) into a [JWKs].
// Each key's KID is auto-computed from the RFC 7638 thumbprint if not present.
func ParsePublicJWKs(data []byte) (JWKs, error) {
	var jwks JWKs
	if err := json.Unmarshal(data, &jwks); err != nil {
		return JWKs{}, err
	}
	return jwks, nil
}

// --- Load functions (source → key) ---

// LoadPublicJWK loads a single JWK from a local file.
//
// source can be a file: URI or a bare file path.
func LoadPublicJWK(source string) (*PublicKey, error) {
	data, err := readSource(source)
	if err != nil {
		return nil, err
	}
	return ParsePublicJWK(data)
}

// LoadPrivateJWK loads a single private JWK from a local file.
//
// source can be a file: URI or a bare file path.
func LoadPrivateJWK(source string) (*PrivateKey, error) {
	data, err := readSource(source)
	if err != nil {
		return nil, err
	}
	return ParsePrivateJWK(data)
}

// LoadPublicJWKs loads a JWKS document from a local file.
//
// source can be a file: URI or a bare file path.
func LoadPublicJWKs(source string) (JWKs, error) {
	data, err := readSource(source)
	if err != nil {
		return JWKs{}, err
	}
	return ParsePublicJWKs(data)
}

// --- Source resolution ---

// readSource resolves a source string to raw bytes from a local file.
//
// Supported sources:
//   - file: URI (file:///path, file://path, file:/path, file:path)
//   - bare file path (/path, ./relative, C:\windows)
func readSource(source string) ([]byte, error) {
	if strings.HasPrefix(source, "file:") {
		source = fileURIToPath(source)
	}
	return os.ReadFile(source)
}

// fileURIToPath extracts a file path from a file: URI.
//
// Handles the common forms:
//   - file:///absolute/path → /absolute/path
//   - file://path           → path (relative, non-standard but common)
//   - file:/absolute/path   → /absolute/path
//   - file:relative/path    → relative/path
func fileURIToPath(uri string) string {
	s := strings.TrimPrefix(uri, "file:")
	s = strings.TrimPrefix(s, "//")
	return s
}
