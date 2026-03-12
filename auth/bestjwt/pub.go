// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package bestjwt

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

// Key is the constraint for the public key type parameter K used in PublicJWK.
//
// All standard-library asymmetric public key types satisfy this interface
// since Go 1.15: *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey.
//
// Note: crypto.PublicKey is defined as interface{} and does NOT satisfy Key.
// Use Key itself as the type argument for heterogeneous collections
// (e.g. []PublicJWK[Key]), since Key declares Equal and therefore satisfies
// its own constraint. Use [TypedKeys] to narrow to a concrete type.
type Key interface {
	Equal(x crypto.PublicKey) bool
}

// PublicJWK wraps a parsed public key with its JWKS metadata.
//
// K is constrained to [Key], providing type-safe access to the underlying
// key without a type assertion at each use site.
//
// For a heterogeneous JWKS endpoint (mixed RSA/EC) use PublicJWK[Key].
// For a homogeneous store use the concrete type directly (e.g.
// PublicJWK[*ecdsa.PublicKey]). Use [TypedKeys] to narrow a mixed slice.
//
// Example — sign with a known key type, no assertion needed:
//
//	ecKeys := bestjwt.TypedKeys[*ecdsa.PublicKey](allKeys)
//	jws.UnsafeVerify(ecKeys[0].Key) // Key is *ecdsa.PublicKey directly
type PublicJWK[K Key] struct {
	Key K
	KID string
	Use string
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

// TypedKeys filters a heterogeneous []PublicJWK[Key] slice to only those whose
// underlying key is of concrete type K, returning a typed []PublicJWK[K].
// Keys of other types are silently skipped.
//
// Example — extract only ECDSA keys from a mixed JWKS result:
//
//	all, _ := bestjwt.FetchPublicJWKs(jwksURL)
//	ecKeys := bestjwt.TypedKeys[*ecdsa.PublicKey](all)
//	rsaKeys := bestjwt.TypedKeys[*rsa.PublicKey](all)
func TypedKeys[K Key](keys []PublicJWK[Key]) []PublicJWK[K] {
	var result []PublicJWK[K]
	for _, k := range keys {
		if typed, ok := k.Key.(K); ok {
			result = append(result, PublicJWK[K]{Key: typed, KID: k.KID, Use: k.Use})
		}
	}
	return result
}

// FetchPublicJWKs retrieves and parses a JWKS document from url.
// Keys are returned as []PublicJWK[Key] since a JWKS endpoint may contain a
// mix of key types. Use [TypedKeys] to narrow to a concrete type.
func FetchPublicJWKs(url string) ([]PublicJWK[Key], error) {
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
func ReadPublicJWKs(filePath string) ([]PublicJWK[Key], error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JWKS file '%s': %w", filePath, err)
	}
	defer func() { _ = file.Close() }()
	return DecodePublicJWKs(file)
}

// UnmarshalPublicJWKs parses a JWKS document from raw JSON bytes.
func UnmarshalPublicJWKs(data []byte) ([]PublicJWK[Key], error) {
	var jwks JWKsJSON
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	return DecodePublicJWKsJSON(jwks)
}

// DecodePublicJWKs parses a JWKS document from an [io.Reader].
func DecodePublicJWKs(r io.Reader) ([]PublicJWK[Key], error) {
	var jwks JWKsJSON
	if err := json.NewDecoder(r).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	return DecodePublicJWKsJSON(jwks)
}

// DecodePublicJWKsJSON converts a parsed [JWKsJSON] into typed public keys.
func DecodePublicJWKsJSON(jwks JWKsJSON) ([]PublicJWK[Key], error) {
	var keys []PublicJWK[Key]
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

// DecodePublicJWK parses a single [PublicJWKJSON] into a PublicJWK[Key].
// Supports RSA (minimum 1024-bit) and EC (P-256, P-384, P-521) keys.
func DecodePublicJWK(jwk PublicJWKJSON) (*PublicJWK[Key], error) {
	switch jwk.Kty {
	case "RSA":
		key, err := decodeRSAPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key '%s': %w", jwk.KID, err)
		}
		if key.Size() < 128 { // 1024 bits minimum
			return nil, fmt.Errorf("RSA key '%s' too small: %d bytes", jwk.KID, key.Size())
		}
		return &PublicJWK[Key]{Key: key, KID: jwk.KID, Use: jwk.Use}, nil

	case "EC":
		key, err := decodeECDSAPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key '%s': %w", jwk.KID, err)
		}
		return &PublicJWK[Key]{Key: key, KID: jwk.KID, Use: jwk.Use}, nil

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
