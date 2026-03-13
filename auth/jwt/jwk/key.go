// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package jwk provides JWK (JSON Web Key) and JWKS (JSON Web Key Set) types
// and key management utilities.
//
// [PublicKey] is the primary in-memory representation of a public key with its
// JWKS metadata (KID, Use, Alg, KeyOps). It implements [json.Marshaler] and
// [json.Unmarshaler], so [JWKs] can be marshalled and unmarshalled directly:
//
//	var jwks jwk.JWKs
//	json.Unmarshal(data, &jwks)   // parse a JWKS document
//	json.Marshal(jwks)             // serialize a JWKS document
//
// For signing, use [PrivateKey] which wraps a [crypto.Signer] and derives its
// [PublicKey] on demand via [PrivateKey.PublicKey].
//
// JSON encoding and decoding are handled transparently — there are no exported
// wire types to deal with.
package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"
)

// CryptoPublicKey is the constraint for public key types stored in [PublicKey].
//
// All standard Go public key types (*ecdsa.PublicKey, *rsa.PublicKey,
// ed25519.PublicKey) implement this interface per the Go standard library
// recommendation.
type CryptoPublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// PublicKey wraps a parsed public key with its JWKS metadata.
//
// PublicKey is the in-memory representation of a JWK. Use the typed accessor
// methods [PublicKey.ECDSA], [PublicKey.RSA], and [PublicKey.EdDSA] to assert
// the underlying type without a raw type switch.
//
// For signing keys, use [PrivateKey] instead — it holds the [crypto.Signer]
// and derives a PublicKey on demand.
type PublicKey struct {
	CryptoPublicKey
	KID    string
	Use    string
	Alg    string
	KeyOps []string
}

// ECDSA returns the key as *ecdsa.PublicKey if it is one, else (nil, false).
func (k PublicKey) ECDSA() (*ecdsa.PublicKey, bool) {
	key, ok := k.CryptoPublicKey.(*ecdsa.PublicKey)
	return key, ok
}

// RSA returns the key as *rsa.PublicKey if it is one, else (nil, false).
func (k PublicKey) RSA() (*rsa.PublicKey, bool) {
	key, ok := k.CryptoPublicKey.(*rsa.PublicKey)
	return key, ok
}

// EdDSA returns the key as ed25519.PublicKey if it is one, else (nil, false).
func (k PublicKey) EdDSA() (ed25519.PublicKey, bool) {
	key, ok := k.CryptoPublicKey.(ed25519.PublicKey)
	return key, ok
}

// KeyType returns the JWK "kty" string for the key: "EC", "RSA", or "OKP".
// Returns "" if the key type is unrecognized.
func (k PublicKey) KeyType() string {
	switch k.CryptoPublicKey.(type) {
	case *ecdsa.PublicKey:
		return "EC"
	case *rsa.PublicKey:
		return "RSA"
	case ed25519.PublicKey:
		return "OKP"
	default:
		return ""
	}
}

// MarshalJSON implements [json.Marshaler], encoding the key as a JWK JSON object.
// Private key fields are never included.
func (k PublicKey) MarshalJSON() ([]byte, error) {
	pk, err := encode(k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pk)
}

// UnmarshalJSON implements [json.Unmarshaler], parsing a JWK JSON object.
// Private key fields (d, p, q, etc.) are silently ignored.
// If the JWK has no "kid" field, the KID is auto-computed via [PublicKey.Thumbprint].
func (k *PublicKey) UnmarshalJSON(data []byte) error {
	var kj rawKey
	if err := json.Unmarshal(data, &kj); err != nil {
		return fmt.Errorf("parse JWK: %w", err)
	}
	decoded, err := decodeOne(kj)
	if err != nil {
		return err
	}
	if decoded.KID == "" {
		decoded.KID, err = decoded.Thumbprint()
		if err != nil {
			return fmt.Errorf("parse JWK: compute thumbprint: %w", err)
		}
	}
	*k = *decoded
	return nil
}

// Thumbprint computes the RFC 7638 JWK Thumbprint (SHA-256 of the canonical
// key JSON with fields in lexicographic order). The result is base64url-encoded.
//
// https://www.rfc-editor.org/rfc/rfc7638.html
//
// Canonical forms per RFC 7638:
//   - EC:  {"crv":…, "kty":"EC", "x":…, "y":…}
//   - RSA: {"e":…, "kty":"RSA", "n":…}
//   - OKP: {"crv":"Ed25519", "kty":"OKP", "x":…}
func (k PublicKey) Thumbprint() (string, error) {
	var canonical []byte
	var err error

	switch key := k.CryptoPublicKey.(type) {
	case *ecdsa.PublicKey:
		b, err := key.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return "", fmt.Errorf("Thumbprint: encode EC key: %w", err)
		}
		byteLen := (key.Curve.Params().BitSize + 7) / 8

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
			X:   base64.RawURLEncoding.EncodeToString(b[1 : 1+byteLen]),
			Y:   base64.RawURLEncoding.EncodeToString(b[1+byteLen:]),
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
		return "", fmt.Errorf("Thumbprint: unsupported key type %T", k.CryptoPublicKey)
	}

	if err != nil {
		return "", fmt.Errorf("Thumbprint: marshal canonical JSON: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// PrivateKey wraps a [crypto.Signer] (private key) with its JWKS metadata.
//
// PrivateKey is never serialized to JSON — it is a runtime-only signing
// capability. Call [PrivateKey.PublicKey] to obtain the serializable [PublicKey].
//
// Because crypto.Signer is embedded, PrivateKey itself satisfies crypto.Signer:
// its Sign and Public methods are promoted directly.
type PrivateKey struct {
	crypto.Signer
	KID    string
	Use    string
	Alg    string
	KeyOps []string
}

// PublicKey derives the [PublicKey] for this signing key.
// The returned PublicKey carries the same KID, Use, Alg, and KeyOps metadata.
func (k *PrivateKey) PublicKey() *PublicKey {
	pub, _ := k.Signer.Public().(CryptoPublicKey)
	return &PublicKey{
		CryptoPublicKey: pub,
		KID:             k.KID,
		Use:             k.Use,
		Alg:             k.Alg,
		KeyOps:          k.KeyOps,
	}
}

// Thumbprint computes the RFC 7638 thumbprint for this key's public side.
// It delegates to [PublicKey.Thumbprint] on the result of [PrivateKey.PublicKey].
func (k *PrivateKey) Thumbprint() (string, error) {
	return k.PublicKey().Thumbprint()
}

// rawKey is the unexported JSON wire representation of a JWK object.
// It is used internally by [PublicKey.MarshalJSON] and [PublicKey.UnmarshalJSON].
type rawKey struct {
	Kty    string   `json:"kty"`
	KID    string   `json:"kid,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	Use    string   `json:"use,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

// JWKs is a JSON Web Key Set. Use json.Marshal and json.Unmarshal directly —
// each [PublicKey] in Keys handles its own encoding via MarshalJSON / UnmarshalJSON.
type JWKs struct {
	Keys []PublicKey `json:"keys"`
}

// encode converts a [PublicKey] to its [rawKey] wire representation.
// Used by [PublicKey.MarshalJSON].
func encode(k PublicKey) (rawKey, error) {
	switch key := k.CryptoPublicKey.(type) {
	case *ecdsa.PublicKey:
		var crv string
		switch key.Curve {
		case elliptic.P256():
			crv = "P-256"
		case elliptic.P384():
			crv = "P-384"
		case elliptic.P521():
			crv = "P-521"
		default:
			return rawKey{}, fmt.Errorf("Encode: unsupported EC curve %s", key.Curve.Params().Name)
		}
		b, err := key.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return rawKey{}, fmt.Errorf("Encode: encode EC key: %w", err)
		}
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		return rawKey{
			Kty:    "EC",
			KID:    k.KID,
			Crv:    crv,
			X:      base64.RawURLEncoding.EncodeToString(b[1 : 1+byteLen]),
			Y:      base64.RawURLEncoding.EncodeToString(b[1+byteLen:]),
			Use:    k.Use,
			Alg:    k.Alg,
			KeyOps: k.KeyOps,
		}, nil

	case *rsa.PublicKey:
		eInt := big.NewInt(int64(key.E))
		return rawKey{
			Kty:    "RSA",
			KID:    k.KID,
			N:      base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:      base64.RawURLEncoding.EncodeToString(eInt.Bytes()),
			Use:    k.Use,
			Alg:    k.Alg,
			KeyOps: k.KeyOps,
		}, nil

	case ed25519.PublicKey:
		return rawKey{
			Kty:    "OKP",
			KID:    k.KID,
			Crv:    "Ed25519",
			X:      base64.RawURLEncoding.EncodeToString([]byte(key)),
			Use:    k.Use,
			Alg:    k.Alg,
			KeyOps: k.KeyOps,
		}, nil

	default:
		return rawKey{}, fmt.Errorf("Encode: unsupported key type %T", k.CryptoPublicKey)
	}
}

// ReadFile reads and parses a JWKS document from a file path.
// It is equivalent to os.ReadFile followed by json.Unmarshal into a [JWKs].
func ReadFile(filePath string) ([]PublicKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JWKS file %q: %w", filePath, err)
	}
	var jwks JWKs
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	return jwks.Keys, nil
}

// decodeOne parses a single rawKey wire struct into a [PublicKey].
// KID auto-derivation from thumbprint is handled by [PublicKey.UnmarshalJSON].
//
// Supported key types:
//   - "RSA" — minimum 1024-bit (RS256)
//   - "EC"  — P-256, P-384, P-521 (ES256, ES384, ES512)
//   - "OKP" — Ed25519 crv (EdDSA, RFC 8037) https://www.rfc-editor.org/rfc/rfc8037.html
func decodeOne(kj rawKey) (*PublicKey, error) {
	switch kj.Kty {
	case "RSA":
		key, err := decodeRSA(kj)
		if err != nil {
			return nil, fmt.Errorf("parse RSA key %q: %w", kj.KID, err)
		}
		if key.Size() < 128 { // 1024 bits minimum
			return nil, fmt.Errorf("RSA key %q too small: %d bytes", kj.KID, key.Size())
		}
		return &PublicKey{CryptoPublicKey: key, KID: kj.KID, Use: kj.Use, Alg: kj.Alg, KeyOps: kj.KeyOps}, nil

	case "EC":
		key, err := decodeEC(kj)
		if err != nil {
			return nil, fmt.Errorf("parse EC key %q: %w", kj.KID, err)
		}
		return &PublicKey{CryptoPublicKey: key, KID: kj.KID, Use: kj.Use, Alg: kj.Alg, KeyOps: kj.KeyOps}, nil

	case "OKP":
		key, err := decodeOKP(kj)
		if err != nil {
			return nil, fmt.Errorf("parse OKP key %q: %w", kj.KID, err)
		}
		return &PublicKey{CryptoPublicKey: key, KID: kj.KID, Use: kj.Use, Alg: kj.Alg, KeyOps: kj.KeyOps}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %q for kid %q", kj.Kty, kj.KID)
	}
}

func decodeRSA(kj rawKey) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(kj.N)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA modulus: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(kj.E)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA exponent: %w", err)
	}

	eInt := new(big.Int).SetBytes(e)
	if !eInt.IsInt64() {
		return nil, fmt.Errorf("RSA exponent too large")
	}
	eVal := eInt.Int64()
	if eVal <= 0 {
		return nil, fmt.Errorf("RSA exponent must be positive")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(eVal),
	}, nil
}

func decodeEC(kj rawKey) (*ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(kj.X)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA X: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(kj.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA Y: %w", err)
	}

	var curve elliptic.Curve
	switch kj.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported EC curve: %s", kj.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func decodeOKP(kj rawKey) (ed25519.PublicKey, error) {
	if kj.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve: %q (only Ed25519 supported)", kj.Crv)
	}
	x, err := base64.RawURLEncoding.DecodeString(kj.X)
	if err != nil {
		return nil, fmt.Errorf("invalid OKP X: %w", err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 key size: got %d bytes, want %d", len(x), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}
