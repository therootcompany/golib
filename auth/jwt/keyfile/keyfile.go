// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package keyfile loads cryptographic keys from local files in JWK, PEM,
// or DER format. All functions auto-compute KID from the RFC 7638 thumbprint
// when not already set.
//
// The Load* functions accept a source string that can be:
//   - A file URI: file:///path/to/key.pem, file://path, file:path
//   - A bare file path: /path/to/key.pem, ./relative, C:\windows\key.pem
//
// The Parse* functions accept raw bytes in the specified format.
//
// For JWK JSON format, the Parse functions in the [jwt] package
// ([jwt.ParsePublicJWK], [jwt.ParsePrivateJWK], [jwt.ParsePublicJWKs])
// can also be used directly.
//
// For fetching keys from remote URLs, use [keyfetch.FetchURL] (JWKS endpoints)
// or fetch the bytes yourself and pass them to Parse*.
package keyfile

import (
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"os"
	"strings"

	"github.com/therootcompany/golib/auth/jwt"
)

// --- Parse functions (bytes → key) ---

// ParsePublicPEM parses a PEM-encoded public key (SPKI "PUBLIC KEY" or
// PKCS#1 "RSA PUBLIC KEY") into a [jwt.PublicKey] with auto-computed KID.
func ParsePublicPEM(data []byte) (*jwt.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found: %w", jwt.ErrInvalidKey)
	}
	return parsePublicPEMBlock(block)
}

// ParsePrivatePEM parses a PEM-encoded private key (PKCS#8 "PRIVATE KEY",
// PKCS#1 "RSA PRIVATE KEY", or SEC 1 "EC PRIVATE KEY") into a
// [jwt.PrivateKey] with auto-computed KID.
func ParsePrivatePEM(data []byte) (*jwt.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("no PEM block found: %w", jwt.ErrInvalidKey)
	}
	return parsePrivatePEMBlock(block)
}

// ParsePublicDER parses a DER-encoded public key into a [jwt.PublicKey] with
// auto-computed KID. It tries SPKI (PKIX) first, then PKCS#1 RSA.
func ParsePublicDER(data []byte) (*jwt.PublicKey, error) {
	// Try SPKI / PKIX (most common modern format).
	if pub, err := x509.ParsePKIXPublicKey(data); err == nil {
		return jwt.FromPublicKey(pub)
	}
	// Try PKCS#1 RSA.
	if pub, err := x509.ParsePKCS1PublicKey(data); err == nil {
		return jwt.FromPublicKey(pub)
	}
	return nil, fmt.Errorf("unrecognized DER public key encoding: %w", jwt.ErrInvalidKey)
}

// ParsePrivateDER parses a DER-encoded private key into a [jwt.PrivateKey]
// with auto-computed KID. It tries PKCS#8 first, then SEC 1 EC, then PKCS#1 RSA.
func ParsePrivateDER(data []byte) (*jwt.PrivateKey, error) {
	// Try PKCS#8 (most common modern format, any algorithm).
	if key, err := x509.ParsePKCS8PrivateKey(data); err == nil {
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key does not implement crypto.Signer: %w", jwt.ErrUnsupportedKeyType)
		}
		return jwt.FromPrivateKey(signer)
	}
	// Try SEC 1 EC.
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return jwt.FromPrivateKey(key)
	}
	// Try PKCS#1 RSA.
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return jwt.FromPrivateKey(key)
	}
	return nil, fmt.Errorf("unrecognized DER private key encoding: %w", jwt.ErrInvalidKey)
}

// --- Load functions (source → key) ---
//
// JWK Load functions are canonical in the [jwk] package and re-exported here
// for convenience so that all key-loading functions are available in one place.

// LoadPublicJWK loads a single JWK from a local file.
// This is a re-export of [jwt.LoadPublicJWK].
func LoadPublicJWK(source string) (*jwt.PublicKey, error) {
	return jwt.LoadPublicJWK(source)
}

// LoadPublicJWKs loads a JWKS document from a local file.
// This is a re-export of [jwt.LoadPublicJWKs].
func LoadPublicJWKs(source string) (jwt.JWKs, error) {
	return jwt.LoadPublicJWKs(source)
}

// LoadPrivateJWK loads a single private JWK from a local file.
// This is a re-export of [jwt.LoadPrivateJWK].
func LoadPrivateJWK(source string) (*jwt.PrivateKey, error) {
	return jwt.LoadPrivateJWK(source)
}

// LoadPublicPEM loads a PEM-encoded public key from a local file.
func LoadPublicPEM(source string) (*jwt.PublicKey, error) {
	data, err := ReadFile(source)
	if err != nil {
		return nil, err
	}
	return ParsePublicPEM(data)
}

// LoadPrivatePEM loads a PEM-encoded private key from a local file.
func LoadPrivatePEM(source string) (*jwt.PrivateKey, error) {
	data, err := ReadFile(source)
	if err != nil {
		return nil, err
	}
	return ParsePrivatePEM(data)
}

// LoadPublicDER loads a DER-encoded public key from a local file.
func LoadPublicDER(source string) (*jwt.PublicKey, error) {
	data, err := ReadFile(source)
	if err != nil {
		return nil, err
	}
	return ParsePublicDER(data)
}

// LoadPrivateDER loads a DER-encoded private key from a local file.
func LoadPrivateDER(source string) (*jwt.PrivateKey, error) {
	data, err := ReadFile(source)
	if err != nil {
		return nil, err
	}
	return ParsePrivateDER(data)
}

// --- Source resolution ---

// ReadFile resolves a source string to raw bytes from a local file.
//
// Supported sources:
//   - file: URI (file:///path, file://path, file:/path, file:path)
//   - bare file path (/path, ./relative, C:\windows)
func ReadFile(source string) ([]byte, error) {
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
	// file:///path → //path after first trim; strip leading slashes down to
	// the path. On Unix file:///etc/key → /etc/key (3 slashes → 1).
	// On Windows file:///C:/key → C:/key.
	s = strings.TrimPrefix(s, "//")
	return s
}

// --- Internal helpers ---

// parsePublicPEMBlock parses a decoded PEM block into a [jwt.PublicKey].
func parsePublicPEMBlock(block *pem.Block) (*jwt.PublicKey, error) {
	switch block.Type {
	case "PUBLIC KEY":
		pub, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SPKI public key: %w: %w", jwt.ErrInvalidKey, err)
		}
		return jwt.FromPublicKey(pub)
	case "RSA PUBLIC KEY":
		pub, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 public key: %w: %w", jwt.ErrInvalidKey, err)
		}
		return jwt.FromPublicKey(pub)
	default:
		return nil, fmt.Errorf("PEM block type %q: %w", block.Type, jwt.ErrUnsupportedFormat)
	}
}

// parsePrivatePEMBlock parses a decoded PEM block into a [jwt.PrivateKey].
func parsePrivatePEMBlock(block *pem.Block) (*jwt.PrivateKey, error) {
	switch block.Type {
	case "PRIVATE KEY":
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#8 private key: %w: %w", jwt.ErrInvalidKey, err)
		}
		signer, ok := key.(crypto.Signer)
		if !ok {
			return nil, fmt.Errorf("PKCS#8 key does not implement crypto.Signer: %w", jwt.ErrUnsupportedKeyType)
		}
		return jwt.FromPrivateKey(signer)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 private key: %w: %w", jwt.ErrInvalidKey, err)
		}
		return jwt.FromPrivateKey(key)
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SEC 1 EC private key: %w: %w", jwt.ErrInvalidKey, err)
		}
		return jwt.FromPrivateKey(key)
	default:
		return nil, fmt.Errorf("PEM block type %q: %w", block.Type, jwt.ErrUnsupportedFormat)
	}
}

