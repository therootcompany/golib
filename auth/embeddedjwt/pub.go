// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package embeddedjwt

import (
	"crypto"
	"crypto/ecdsa"
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

// Key is the interface satisfied by all standard-library asymmetric public key
// types since Go 1.15: *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey.
//
// It is used as the field type in [PublicJWK] so that a single slice can hold
// mixed key types, and as the parameter type of [JWS.UnsafeVerify] so that
// callers can pass PublicJWK.Key directly without a type assertion.
type Key interface {
	Equal(x crypto.PublicKey) bool
}

// PublicJWK wraps a parsed public key with its JWKS metadata.
//
// Key is stored as the [Key] interface to allow mixed RSA/EC slices from a
// real JWKS endpoint. Use the [PublicJWK.ECDSA] and [PublicJWK.RSA] accessor
// methods to obtain a typed key when the algorithm is known.
//
// Example:
//
//	keys, _ := embeddedjwt.FetchPublicJWKs(jwksURL)
//	for _, k := range keys {
//	    if ec, ok := k.ECDSA(); ok {
//	        jws.UnsafeVerify(ec)
//	    }
//	}
type PublicJWK struct {
	Key Key
	KID string
	Use string
}

// ECDSA returns the underlying key as *ecdsa.PublicKey, or (nil, false).
func (p PublicJWK) ECDSA() (*ecdsa.PublicKey, bool) {
	k, ok := p.Key.(*ecdsa.PublicKey)
	return k, ok
}

// RSA returns the underlying key as *rsa.PublicKey, or (nil, false).
func (p PublicJWK) RSA() (*rsa.PublicKey, bool) {
	k, ok := p.Key.(*rsa.PublicKey)
	return k, ok
}

// PublicJWKJSON is the JSON representation of a single key in a JWKS document.
type PublicJWKJSON struct {
	Kty string `json:"kty"`
	KID string `json:"kid"`
	N   string `json:"n,omitempty"` // RSA modulus
	E   string `json:"e,omitempty"` // RSA exponent
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Use string `json:"use,omitempty"`
}

// JWKsJSON is the JSON representation of a JWKS document.
type JWKsJSON struct {
	Keys []PublicJWKJSON `json:"keys"`
}

// FetchPublicJWKs retrieves and parses a JWKS document from url.
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
		return nil, fmt.Errorf("failed to open JWKS file '%s': %w", filePath, err)
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

// DecodePublicJWKsJSON converts a parsed [JWKsJSON] into public keys.
func DecodePublicJWKsJSON(jwks JWKsJSON) ([]PublicJWK, error) {
	var keys []PublicJWK
	for _, jwk := range jwks.Keys {
		key, err := DecodePublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public jwk '%s': %w", jwk.KID, err)
		}
		keys = append(keys, *key)
	}
	if len(keys) == 0 {
		return nil, fmt.Errorf("no valid RSA or ECDSA keys found")
	}
	return keys, nil
}

// DecodePublicJWK parses a single [PublicJWKJSON] into a PublicJWK.
// Supports RSA (minimum 1024-bit) and EC (P-256, P-384, P-521) keys.
func DecodePublicJWK(jwk PublicJWKJSON) (*PublicJWK, error) {
	switch jwk.Kty {
	case "RSA":
		key, err := decodeRSAPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key '%s': %w", jwk.KID, err)
		}
		if key.Size() < 128 { // 1024 bits minimum
			return nil, fmt.Errorf("RSA key '%s' too small: %d bytes", jwk.KID, key.Size())
		}
		return &PublicJWK{Key: key, KID: jwk.KID, Use: jwk.Use}, nil

	case "EC":
		key, err := decodeECDSAPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key '%s': %w", jwk.KID, err)
		}
		return &PublicJWK{Key: key, KID: jwk.KID, Use: jwk.Use}, nil

	default:
		return nil, fmt.Errorf("unsupported key type '%s' for kid '%s'", jwk.Kty, jwk.KID)
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

func decodeECDSAPublicJWK(jwk PublicJWKJSON) (*ecdsa.PublicKey, error) {
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
		return nil, fmt.Errorf("unsupported ECDSA curve: %s", jwk.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
