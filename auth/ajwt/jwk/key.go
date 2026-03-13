// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package jwk provides JWK (JSON Web Key) and JWKS (JSON Web Key Set) types,
// encoding, decoding, and key management utilities.
//
// The [Key] type is the primary in-memory representation of a public key with
// its JWKS metadata (KID, Use). Encoding converts [Key] to [KeyJSON] or JSON
// bytes; decoding parses them back. Fetching retrieves JWKS documents from
// remote endpoints.
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
	"io"
	"math/big"
	"os"
)

// PublicKey is the constraint for public key types stored in [Key].
//
// All standard Go public key types (*ecdsa.PublicKey, *rsa.PublicKey,
// ed25519.PublicKey) implement this interface per the Go standard library
// recommendation.
type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// Key wraps a parsed public key with its JWKS metadata.
//
// Key is the in-memory representation of a JWK. Use the typed accessor methods
// [Key.ECDSA], [Key.RSA], and [Key.EdDSA] to assert the underlying type
// without a raw type switch.
type Key struct {
	Key PublicKey
	KID string
	Use string
}

// ECDSA returns the key as *ecdsa.PublicKey if it is one, else (nil, false).
func (k Key) ECDSA() (*ecdsa.PublicKey, bool) {
	key, ok := k.Key.(*ecdsa.PublicKey)
	return key, ok
}

// RSA returns the key as *rsa.PublicKey if it is one, else (nil, false).
func (k Key) RSA() (*rsa.PublicKey, bool) {
	key, ok := k.Key.(*rsa.PublicKey)
	return key, ok
}

// EdDSA returns the key as ed25519.PublicKey if it is one, else (nil, false).
func (k Key) EdDSA() (ed25519.PublicKey, bool) {
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
func (k Key) Thumbprint() (string, error) {
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

// KeyJSON is the JSON representation of a single key in a JWKS document.
type KeyJSON struct {
	Kty string `json:"kty"`
	KID string `json:"kid"`
	Crv string `json:"crv,omitempty"` // EC / OKP curve
	X   string `json:"x,omitempty"`   // EC / OKP public key x (or Ed25519 key bytes)
	Y   string `json:"y,omitempty"`   // EC public key y
	N   string `json:"n,omitempty"`   // RSA modulus
	E   string `json:"e,omitempty"`   // RSA exponent
	Use string `json:"use,omitempty"`
}

// SetJSON is the JSON representation of a JWKS document (a set of keys).
type SetJSON struct {
	Keys []KeyJSON `json:"keys"`
}

// Encode converts a [Key] to its [KeyJSON] representation.
//
// Supported key types: *ecdsa.PublicKey (EC), *rsa.PublicKey (RSA), ed25519.PublicKey (OKP).
func Encode(k Key) (KeyJSON, error) {
	switch key := k.Key.(type) {
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
			return KeyJSON{}, fmt.Errorf("Encode: unsupported EC curve %s", key.Curve.Params().Name)
		}
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		xBytes := make([]byte, byteLen)
		yBytes := make([]byte, byteLen)
		key.X.FillBytes(xBytes)
		key.Y.FillBytes(yBytes)
		return KeyJSON{
			Kty: "EC",
			KID: k.KID,
			Crv: crv,
			X:   base64.RawURLEncoding.EncodeToString(xBytes),
			Y:   base64.RawURLEncoding.EncodeToString(yBytes),
			Use: k.Use,
		}, nil

	case *rsa.PublicKey:
		eInt := big.NewInt(int64(key.E))
		return KeyJSON{
			Kty: "RSA",
			KID: k.KID,
			N:   base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(eInt.Bytes()),
			Use: k.Use,
		}, nil

	case ed25519.PublicKey:
		return KeyJSON{
			Kty: "OKP",
			KID: k.KID,
			Crv: "Ed25519",
			X:   base64.RawURLEncoding.EncodeToString([]byte(key)),
			Use: k.Use,
		}, nil

	default:
		return KeyJSON{}, fmt.Errorf("Encode: unsupported key type %T", k.Key)
	}
}

// EncodeSet converts a slice of [Key] to a [SetJSON] struct.
func EncodeSet(keys []Key) (SetJSON, error) {
	jsonKeys := make([]KeyJSON, 0, len(keys))
	for _, k := range keys {
		jk, err := Encode(k)
		if err != nil {
			return SetJSON{}, err
		}
		jsonKeys = append(jsonKeys, jk)
	}
	return SetJSON{Keys: jsonKeys}, nil
}

// Marshal serializes a slice of [Key] as a JWKS JSON document.
func Marshal(keys []Key) ([]byte, error) {
	doc, err := EncodeSet(keys)
	if err != nil {
		return nil, err
	}
	return json.Marshal(doc)
}

// ReadFile reads and parses a JWKS document from a file path.
func ReadFile(filePath string) ([]Key, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JWKS file %q: %w", filePath, err)
	}
	defer func() { _ = file.Close() }()
	return Decode(file)
}

// Unmarshal parses a JWKS document from raw JSON bytes.
func Unmarshal(data []byte) ([]Key, error) {
	var set SetJSON
	if err := json.Unmarshal(data, &set); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	return DecodeSetJSON(set)
}

// Decode parses a JWKS document from an [io.Reader].
func Decode(r io.Reader) ([]Key, error) {
	var set SetJSON
	if err := json.NewDecoder(r).Decode(&set); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	return DecodeSetJSON(set)
}

// DecodeSetJSON converts a parsed [SetJSON] into typed public keys.
//
// If a key has no kid field in the source document, the KID is auto-populated
// from [Key.Thumbprint] per RFC 7638.
func DecodeSetJSON(set SetJSON) ([]Key, error) {
	var keys []Key
	for _, kj := range set.Keys {
		key, err := DecodeOne(kj)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public jwk %q: %w", kj.KID, err)
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

// DecodeOne parses a single [KeyJSON] into a [Key].
//
// Supported key types:
//   - "RSA" — minimum 1024-bit (RS256)
//   - "EC"  — P-256, P-384, P-521 (ES256, ES384, ES512)
//   - "OKP" — Ed25519 crv (EdDSA / RFC 8037)
func DecodeOne(kj KeyJSON) (*Key, error) {
	switch kj.Kty {
	case "RSA":
		key, err := decodeRSA(kj)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key %q: %w", kj.KID, err)
		}
		if key.Size() < 128 { // 1024 bits minimum
			return nil, fmt.Errorf("RSA key %q too small: %d bytes", kj.KID, key.Size())
		}
		return &Key{Key: key, KID: kj.KID, Use: kj.Use}, nil

	case "EC":
		key, err := decodeEC(kj)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key %q: %w", kj.KID, err)
		}
		return &Key{Key: key, KID: kj.KID, Use: kj.Use}, nil

	case "OKP":
		key, err := decodeOKP(kj)
		if err != nil {
			return nil, fmt.Errorf("failed to parse OKP key %q: %w", kj.KID, err)
		}
		return &Key{Key: key, KID: kj.KID, Use: kj.Use}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %q for kid %q", kj.Kty, kj.KID)
	}
}

func decodeRSA(kj KeyJSON) (*rsa.PublicKey, error) {
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

func decodeEC(kj KeyJSON) (*ecdsa.PublicKey, error) {
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

func decodeOKP(kj KeyJSON) (ed25519.PublicKey, error) {
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
