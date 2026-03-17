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
// The Load* functions accept a file path and read from the local filesystem.
// The Parse* functions accept raw bytes, suitable for use with [embed.FS]
// or any other byte source.
//
// For JWK JSON format, the Parse functions in the [jwt] package
// ([jwt.ParsePublicJWK], [jwt.ParsePrivateJWK], [jwt.ParseWellKnownJWKs])
// can also be used directly.
//
// For fetching keys from remote URLs, use [keyfetch.FetchURL] (JWKS endpoints)
// or fetch the bytes yourself and pass them to Parse*.
package keyfile

import (
	"crypto"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/therootcompany/golib/auth/jwt"
	"os"
)

// --- Parse functions (bytes => key) ---

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
	return nil, fmt.Errorf("unrecognized DER public key encoding (tried PKIX, PKCS1): %w", jwt.ErrInvalidKey)
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
		return fullPrivateKey(signer)
	}
	// Try SEC 1 EC.
	if key, err := x509.ParseECPrivateKey(data); err == nil {
		return fullPrivateKey(key)
	}
	// Try PKCS#1 RSA.
	if key, err := x509.ParsePKCS1PrivateKey(data); err == nil {
		return fullPrivateKey(key)
	}
	return nil, fmt.Errorf("unrecognized DER private key encoding (tried PKCS8, EC, PKCS1): %w", jwt.ErrInvalidKey)
}

// --- Load functions (file path => key) ---

// LoadPublicJWK loads a single JWK from a local file.
func LoadPublicJWK(path string) (*jwt.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParsePublicJWK(data)
}

// LoadPrivateJWK loads a single private JWK from a local file.
func LoadPrivateJWK(path string) (*jwt.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParsePrivateJWK(data)
}

// LoadWellKnownJWKs loads a JWKS document from a local file.
func LoadWellKnownJWKs(path string) (jwt.WellKnownJWKs, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return jwt.WellKnownJWKs{}, err
	}
	return jwt.ParseWellKnownJWKs(data)
}

// --- Save functions (key => file) ---

// SavePublicJWK writes a single public key as a JWK JSON file.
// The file is created with mode 0644 (world-readable).
func SavePublicJWK(path string, pub *jwt.PublicKey) error {
	data, err := json.Marshal(pub)
	if err != nil {
		return fmt.Errorf("marshal public JWK: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

// SavePublicJWKs writes a JWKS document ({"keys": [...]}) as a JSON file.
// The file is created with mode 0644 (world-readable).
func SavePublicJWKs(path string, keys []jwt.PublicKey) error {
	jwks := jwt.WellKnownJWKs{Keys: keys}
	data, err := json.Marshal(jwks)
	if err != nil {
		return fmt.Errorf("marshal JWKS: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0644)
}

// SavePrivateJWK writes a single private key as a JWK JSON file.
// The file is created with mode 0600 (owner-only).
func SavePrivateJWK(path string, priv *jwt.PrivateKey) error {
	data, err := json.Marshal(priv)
	if err != nil {
		return fmt.Errorf("marshal private JWK: %w", err)
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

// LoadPublicPEM loads a PEM-encoded public key from a local file.
func LoadPublicPEM(path string) (*jwt.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicPEM(data)
}

// LoadPrivatePEM loads a PEM-encoded private key from a local file.
func LoadPrivatePEM(path string) (*jwt.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivatePEM(data)
}

// LoadPublicDER loads a DER-encoded public key from a local file.
func LoadPublicDER(path string) (*jwt.PublicKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePublicDER(data)
}

// LoadPrivateDER loads a DER-encoded private key from a local file.
func LoadPrivateDER(path string) (*jwt.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParsePrivateDER(data)
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
		return fullPrivateKey(signer)
	case "RSA PRIVATE KEY":
		key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse PKCS#1 private key: %w: %w", jwt.ErrInvalidKey, err)
		}
		return fullPrivateKey(key)
	case "EC PRIVATE KEY":
		key, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("parse SEC 1 EC private key: %w: %w", jwt.ErrInvalidKey, err)
		}
		return fullPrivateKey(key)
	default:
		return nil, fmt.Errorf("PEM block type %q: %w", block.Type, jwt.ErrUnsupportedFormat)
	}
}

// fullPrivateKey wraps a crypto.Signer into a *PrivateKey with
// auto-computed KID (thumbprint) for file-loaded keys.
func fullPrivateKey(signer crypto.Signer) (*jwt.PrivateKey, error) {
	pk, err := jwt.FromPrivateKey(signer, "")
	if err != nil {
		return nil, err
	}
	pub, err := pk.PublicKey()
	if err != nil {
		return nil, fmt.Errorf("derive public key: %w", err)
	}
	kid, err := pub.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("compute thumbprint: %w", err)
	}
	pk.KID = kid
	return pk, nil
}
