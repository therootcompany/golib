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
// [Key] is the primary in-memory representation of a public key with its JWKS
// metadata (KID, Use, Alg, KeyOps). It implements [json.Marshaler] and
// [json.Unmarshaler], so [JWKs] can be marshalled and unmarshalled directly:
//
//	var jwks jwk.JWKs
//	json.Unmarshal(data, &jwks)   // parse a JWKS document
//	json.Marshal(jwks)             // serialize a JWKS document
//
// [PublicKey] and [PrivateKey] are the JSON wire structs. Private key fields
// (d, p, q, etc.) are silently ignored when parsing into [Key]; use [PrivateKey]
// explicitly when you need to read private key material from JSON.
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

// CryptoPublicKey is the constraint for public key types stored in [Key].
//
// All standard Go public key types (*ecdsa.PublicKey, *rsa.PublicKey,
// ed25519.PublicKey) implement this interface per the Go standard library
// recommendation.
type CryptoPublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// Key wraps a parsed public key with its JWKS metadata.
//
// Key is the in-memory representation of a JWK. Use the typed accessor methods
// [Key.ECDSA], [Key.RSA], and [Key.EdDSA] to assert the underlying type
// without a raw type switch.
//
// For signing keys, set Signer to the [crypto.Signer] for the private key.
// Signer is never serialized to JSON — it is a runtime-only capability.
// If Key (the public side) is not set, it is derived from Signer.Public()
// on demand (e.g. by [Key.Thumbprint]).
type Key struct {
	Key    CryptoPublicKey
	Signer crypto.Signer // non-nil for signing keys; never serialized
	KID    string
	Use    string
	Alg    string
	KeyOps []string
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

// KeyType returns the JWK "kty" string for the key: "EC", "RSA", or "OKP".
// Returns "" if the key type is unrecognized.
func (k Key) KeyType() string {
	switch k.Key.(type) {
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
// Private key fields are never included; use [PrivateKey] for private key material.
func (k Key) MarshalJSON() ([]byte, error) {
	pk, err := encode(k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pk)
}

// UnmarshalJSON implements [json.Unmarshaler], parsing a JWK JSON object.
// Private key fields (d, p, q, etc.) are silently ignored — use [PrivateKey] for those.
// If the JWK has no "kid" field, the KID is auto-computed via [Key.Thumbprint].
func (k *Key) UnmarshalJSON(data []byte) error {
	var kj PublicKey
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
func (k Key) Thumbprint() (string, error) {
	var canonical []byte
	var err error

	pub := k.Key
	if pub == nil && k.Signer != nil {
		var ok bool
		pub, ok = k.Signer.Public().(CryptoPublicKey)
		if !ok {
			return "", fmt.Errorf("Thumbprint: signer public key type %T does not implement CryptoPublicKey", k.Signer.Public())
		}
	}

	switch key := pub.(type) {
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
		return "", fmt.Errorf("Thumbprint: unsupported key type %T", k.Key)
	}

	if err != nil {
		return "", fmt.Errorf("Thumbprint: marshal canonical JSON: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// PublicKey is the JSON representation of a single key in a JWKS document.
type PublicKey struct {
	Kty    string   `json:"kty"`
	KID    string   `json:"kid"`
	Crv    string   `json:"crv,omitempty"`     // EC / OKP curve
	X      string   `json:"x,omitempty"`       // EC / OKP public key x (or Ed25519 key bytes)
	Y      string   `json:"y,omitempty"`       // EC public key y
	N      string   `json:"n,omitempty"`       // RSA modulus
	E      string   `json:"e,omitempty"`       // RSA exponent
	Use    string   `json:"use,omitempty"`     // intended use: "sig" or "enc"
	Alg    string   `json:"alg,omitempty"`     // algorithm hint, e.g. "RS256", "ES256", "EdDSA"
	KeyOps []string `json:"key_ops,omitempty"` // allowed operations, e.g. ["sign"], ["verify"]
}

// JWKs is a JSON Web Key Set. Use json.Marshal and json.Unmarshal directly —
// each [Key] in Keys handles its own encoding via MarshalJSON / UnmarshalJSON.
type JWKs struct {
	Keys []Key `json:"keys"`
}

// PrivateKey is the JSON representation of a private JWK.
//
// It embeds [PublicKey] for the public fields and adds the private key
// material. Use [PrivateKey.PublicJWK] to extract only the public portion —
// this is the only way to convert a PrivateKey to a PublicKey, making
// accidental serialization of private key material explicit and visible.
//
// Private fields per the respective RFCs:
//   - EC:  RFC 7518 §6.2.2 https://www.rfc-editor.org/rfc/rfc7518.html#section-6.2.2
//   - RSA: RFC 7518 §6.3.2 https://www.rfc-editor.org/rfc/rfc7518.html#section-6.3.2
//   - OKP: RFC 8037        https://www.rfc-editor.org/rfc/rfc8037.html
//   - D:  EC/OKP private scalar; RSA private exponent
//   - P, Q: RSA prime factors (optional, for CRT)
//   - Dp, Dq, Qi: RSA CRT exponents and coefficient (optional)
type PrivateKey struct {
	PublicKey
	D  string `json:"d,omitempty"`  // EC/OKP private scalar; RSA private exponent
	P  string `json:"p,omitempty"`  // RSA first prime factor (CRT)
	Q  string `json:"q,omitempty"`  // RSA second prime factor (CRT)
	Dp string `json:"dp,omitempty"` // RSA first factor CRT exponent
	Dq string `json:"dq,omitempty"` // RSA second factor CRT exponent
	Qi string `json:"qi,omitempty"` // RSA first CRT coefficient
}

// PublicJWK returns the public portion of this private key as a [PublicKey].
//
// This is the only way to obtain a PublicKey from a PrivateKey —
// the conversion is explicit and visible, preventing accidental disclosure
// of private key material.
func (k PrivateKey) PublicJWK() PublicKey { return k.PublicKey }

// encode converts a [Key] to its [PublicKey] wire representation.
// Used by [Key.MarshalJSON].
func encode(k Key) (PublicKey, error) {
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
			return PublicKey{}, fmt.Errorf("Encode: unsupported EC curve %s", key.Curve.Params().Name)
		}
		b, err := key.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return PublicKey{}, fmt.Errorf("Encode: encode EC key: %w", err)
		}
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		return PublicKey{
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
		return PublicKey{
			Kty:    "RSA",
			KID:    k.KID,
			N:      base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
			E:      base64.RawURLEncoding.EncodeToString(eInt.Bytes()),
			Use:    k.Use,
			Alg:    k.Alg,
			KeyOps: k.KeyOps,
		}, nil

	case ed25519.PublicKey:
		return PublicKey{
			Kty:    "OKP",
			KID:    k.KID,
			Crv:    "Ed25519",
			X:      base64.RawURLEncoding.EncodeToString([]byte(key)),
			Use:    k.Use,
			Alg:    k.Alg,
			KeyOps: k.KeyOps,
		}, nil

	default:
		return PublicKey{}, fmt.Errorf("Encode: unsupported key type %T", k.Key)
	}
}

// ReadFile reads and parses a JWKS document from a file path.
func ReadFile(filePath string) ([]Key, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JWKS file %q: %w", filePath, err)
	}
	return Decode(data)
}

// Decode parses a JWKS document from raw JSON bytes.
// Each key's KID is auto-computed via [Key.Thumbprint] if absent.
func Decode(data []byte) ([]Key, error) {
	var jwks JWKs
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}
	if len(jwks.Keys) == 0 {
		return nil, fmt.Errorf("no valid keys found in JWKS")
	}
	return jwks.Keys, nil
}

// decodeOne parses a single [PublicKey] wire struct into a [Key].
// KID auto-derivation from thumbprint is handled by [Key.UnmarshalJSON].
//
// Supported key types:
//   - "RSA" — minimum 1024-bit (RS256)
//   - "EC"  — P-256, P-384, P-521 (ES256, ES384, ES512)
//   - "OKP" — Ed25519 crv (EdDSA, RFC 8037) https://www.rfc-editor.org/rfc/rfc8037.html
func decodeOne(kj PublicKey) (*Key, error) {
	switch kj.Kty {
	case "RSA":
		key, err := decodeRSA(kj)
		if err != nil {
			return nil, fmt.Errorf("parse RSA key %q: %w", kj.KID, err)
		}
		if key.Size() < 128 { // 1024 bits minimum
			return nil, fmt.Errorf("RSA key %q too small: %d bytes", kj.KID, key.Size())
		}
		return &Key{Key: key, KID: kj.KID, Use: kj.Use, Alg: kj.Alg, KeyOps: kj.KeyOps}, nil

	case "EC":
		key, err := decodeEC(kj)
		if err != nil {
			return nil, fmt.Errorf("parse EC key %q: %w", kj.KID, err)
		}
		return &Key{Key: key, KID: kj.KID, Use: kj.Use, Alg: kj.Alg, KeyOps: kj.KeyOps}, nil

	case "OKP":
		key, err := decodeOKP(kj)
		if err != nil {
			return nil, fmt.Errorf("parse OKP key %q: %w", kj.KID, err)
		}
		return &Key{Key: key, KID: kj.KID, Use: kj.Use, Alg: kj.Alg, KeyOps: kj.KeyOps}, nil

	default:
		return nil, fmt.Errorf("unsupported key type %q for kid %q", kj.Kty, kj.KID)
	}
}

func decodeRSA(kj PublicKey) (*rsa.PublicKey, error) {
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

func decodeEC(kj PublicKey) (*ecdsa.PublicKey, error) {
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

func decodeOKP(kj PublicKey) (ed25519.PublicKey, error) {
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
