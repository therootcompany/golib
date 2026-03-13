// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package ajwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

// PublicJWK wraps a parsed public key with its JWKS metadata.
//
// Key is [crypto.PublicKey] (= any) since a JWKS endpoint returns a
// heterogeneous mix of key types determined at runtime by the "kty" field.
// Use the typed accessor methods [PublicJWK.ECDSA], [PublicJWK.RSA], and
// [PublicJWK.EdDSA] to assert the underlying type without a raw type switch.
type PublicJWK struct {
	Key crypto.PublicKey
	KID string
	Use string
}

// ECDSA returns the key as *ecdsa.PublicKey if it is one, else (nil, false).
func (k PublicJWK) ECDSA() (*ecdsa.PublicKey, bool) {
	key, ok := k.Key.(*ecdsa.PublicKey)
	return key, ok
}

// RSA returns the key as *rsa.PublicKey if it is one, else (nil, false).
func (k PublicJWK) RSA() (*rsa.PublicKey, bool) {
	key, ok := k.Key.(*rsa.PublicKey)
	return key, ok
}

// EdDSA returns the key as ed25519.PublicKey if it is one, else (nil, false).
func (k PublicJWK) EdDSA() (ed25519.PublicKey, bool) {
	key, ok := k.Key.(ed25519.PublicKey)
	return key, ok
}

// PublicJWKJSON is the JSON representation of a single key in a JWKS document.
type PublicJWKJSON struct {
	Kty string `json:"kty"`
	KID string `json:"kid"`
	Crv string `json:"crv,omitempty"` // EC / OKP curve
	X   string `json:"x,omitempty"`   // EC / OKP public key x (or Ed25519 key bytes)
	Y   string `json:"y,omitempty"`   // EC public key y
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	Use string `json:"use,omitempty"`
}

// JWKsJSON is the JSON representation of a JWKS document.
type JWKsJSON struct {
	Keys []PublicJWKJSON `json:"keys"`
}

// FetchPublicJWKs retrieves and parses a JWKS document from url.
//
// For issuer-scoped key management with context support, use
// [Issuer.FetchKeys] instead.
func FetchPublicJWKs(url string) ([]PublicJWK, error) {
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	return DecodePublicJWKs(resp.Body)
}

// ReadPublicJWKs reads and parses a JWKS document from a file path.
func ReadPublicJWKs(filePath string) ([]PublicJWK, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JWKS file %q: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()
	return DecodePublicJWKs(file)
}

// UnmarshalPublicJWKs parses a JWKS document from raw JSON bytes.
func UnmarshalPublicJWKs(data []byte) ([]PublicJWK, error) {
	var jwks JWKsJSON
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	return DecodePublicJWKsJSON(jwks)
}

// DecodePublicJWKs parses a JWKS document from an [io.Reader].
func DecodePublicJWKs(r io.Reader) ([]PublicJWK, error) {
	var jwks JWKsJSON
	if err := json.NewDecoder(r).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	return DecodePublicJWKsJSON(jwks)
}

// DecodePublicJWKsJSON converts a parsed [JWKsJSON] into typed public keys.
func DecodePublicJWKsJSON(jwks JWKsJSON) ([]PublicJWK, error) {
	var keys []PublicJWK
	for _, jwk := range jwks.Keys {
		key, err := DecodePublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public jwk %q: %w", jwk.KID, err)
		}
		keys = append(keys, *key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in JWKS")
	}
	return keys, nil
}

// DecodePublicJWK parses a single [PublicJWKJSON] into a [PublicJWK].
//
// Supported key types:
//   - "RSA" — minimum 1024-bit (RS256)
//   - "EC"  — P-256, P-384, P-521 (ES256, ES384, ES512)
//   - "OKP" — Ed25519 crv (EdDSA / RFC 8037)
func DecodePublicJWK(jwk PublicJWKJSON) (*PublicJWK, error) {
	switch jwk.Kty {
	case "RSA":
		key, err := decodeRSAPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key %q: %w", jwk.KID, err)
		}
		if key.Size() < 128 { // 1024 bits minimum
			return nil, fmt.Errorf("RSA key %q too small: %d bytes", jwk.KID, key.Size())
		}
		return &PublicJWK{Key: key, KID: jwk.KID, Use: jwk.Use}, nil

	case "EC":
		key, err := decodeECPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key %q: %w", jwk.KID, err)
		}
		return &PublicJWK{Key: key, KID: jwk.KID, Use: jwk.Use}, nil

	case "OKP":
		key, err := decodeOKPPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OKP key %q: %w", jwk.KID, err)
		}
		return &PublicJWK{Key: key, KID: jwk.KID, Use: jwk.Use}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %q for kid %q", jwk.Kty, jwk.KID)
	}
}

func decodeRSAPublicJWK(jwk PublicJWKJSON) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA modulus: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA exponent: %w", err)
	}

	eInt := new(big.Int).SetBytes(e).Int64()
	if eInt > int64(^uint(0)>>1) || eInt < 0 {
		return nil, fmt.Errorf("RSA exponent too large or negative")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(eInt),
	}, nil
}

func decodeECPublicJWK(jwk PublicJWKJSON) (*ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA X: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA Y: %w", err)
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", jwk.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func decodeOKPPublicJWK(jwk PublicJWKJSON) (ed25519.PublicKey, error) {
	if jwk.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %q (only Ed25519 supported)", jwk.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid OKP X: %w", err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 key size: got %d bytes, want %d", len(x), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}
