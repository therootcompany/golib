// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package ajwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"strings"
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

// Thumbprint computes the RFC 7638 JWK Thumbprint (SHA-256 of the canonical
// key JSON with fields in lexicographic order). The result is base64url-encoded.
//
// Canonical forms per RFC 7638:
//   - EC:  {"crv":…, "kty":"EC", "x":…, "y":…}
//   - RSA: {"e":…, "kty":"RSA", "n":…}
//   - OKP: {"crv":"Ed25519", "kty":"OKP", "x":…}
//
// Use Thumbprint as KID when none is provided in the JWKS source.
func (k PublicJWK) Thumbprint() (string, error) {
	var canonical []byte
	var err error

	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		xBytes := make([]byte, byteLen)
		yBytes := make([]byte, byteLen)
		key.X.FillBytes(xBytes)
		key.Y.FillBytes(yBytes)

		var crv string
		switch key.Curve {
		case elliptic.P256():
			crv = "P-256"
		case elliptic.P384():
			crv = "P-384"
		case elliptic.P521():
			crv = "P-521"
		default:
			return "", fmt.Errorf("Thumbprint: unsupported EC curve %s", key.Curve.Params().Name)
		}

		// Fields in lexicographic order: crv, kty, x, y
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{
			Crv: crv,
			Kty: "EC",
			X:   base64.RawURLEncoding.EncodeToString(xBytes),
			Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		})

	case *rsa.PublicKey:
		eInt := big.NewInt(int64(key.E))

		// Fields in lexicographic order: e, kty, n
		canonical, err = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{
			E:   base64.RawURLEncoding.EncodeToString(eInt.Bytes()),
			Kty: "RSA",
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		})

	case ed25519.PublicKey:
		// Fields in lexicographic order: crv, kty, x
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{
			Crv: "Ed25519",
			Kty: "OKP",
			X:   base64.RawURLEncoding.EncodeToString([]byte(key)),
		})

	default:
		return "", fmt.Errorf("Thumbprint: unsupported key type %T", k.Key)
	}

	if err != nil {
		return "", fmt.Errorf("Thumbprint: marshal canonical JSON: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
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

// FetchJWKs retrieves and parses a JWKS document from jwksURL.
//
// ctx is used for the HTTP request timeout and cancellation.
func FetchJWKs(ctx context.Context, jwksURL string) ([]PublicJWK, error) {
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
	return DecodePublicJWKs(resp.Body)
}

// FetchJWKsFromOIDC fetches JWKS via OIDC discovery from baseURL.
//
// It fetches {baseURL}/.well-known/openid-configuration and reads the jwks_uri field.
func FetchJWKsFromOIDC(ctx context.Context, baseURL string) ([]PublicJWK, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"
	keys, _, err := fetchJWKsFromDiscovery(ctx, discoveryURL)
	return keys, err
}

// FetchJWKsFromOAuth2 fetches JWKS via OAuth 2.0 authorization server metadata (RFC 8414)
// from baseURL.
//
// It fetches {baseURL}/.well-known/oauth-authorization-server and reads the jwks_uri field.
func FetchJWKsFromOAuth2(ctx context.Context, baseURL string) ([]PublicJWK, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server"
	keys, _, err := fetchJWKsFromDiscovery(ctx, discoveryURL)
	return keys, err
}

// fetchJWKsFromDiscovery fetches a discovery document from discoveryURL, then
// fetches the JWKS from the jwks_uri field. Returns the keys and the issuer
// URL from the discovery document's "issuer" field.
func fetchJWKsFromDiscovery(ctx context.Context, discoveryURL string) ([]PublicJWK, string, error) {
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

	keys, err := FetchJWKs(ctx, doc.JWKsURI)
	if err != nil {
		return nil, "", err
	}
	return keys, doc.Issuer, nil
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
//
// If a key has no kid field in the source document, the KID is auto-populated
// from [PublicJWK.Thumbprint] per RFC 7638.
func DecodePublicJWKsJSON(jwks JWKsJSON) ([]PublicJWK, error) {
	var keys []PublicJWK
	for _, jwk := range jwks.Keys {
		key, err := DecodePublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public jwk %q: %w", jwk.KID, err)
		}
		if key.KID == "" {
			key.KID, err = key.Thumbprint()
			if err != nil {
				return nil, fmt.Errorf("compute thumbprint for kid-less key: %w", err)
			}
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
