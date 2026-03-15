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
// JSON encoding and decoding are handled transparently - there are no exported
// wire types to deal with.
package jwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"os"

	"github.com/therootcompany/golib/auth/jwt/internal/jwa"
	"github.com/therootcompany/golib/auth/jwt/jose"
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
// PublicKey is the in-memory representation of a JWK.
// [PublicKey.KeyType] returns the JWK kty string ("EC", "RSA", or "OKP").
// To access the raw Go key, type-switch on [PublicKey.CryptoPublicKey] -
// see [PublicKey.KeyType] for an example.
//
// For signing keys, use [PrivateKey] instead - it holds the [crypto.Signer]
// and derives a PublicKey on demand.
type PublicKey struct {
	CryptoPublicKey
	KID    string
	Use    string
	Alg    string
	KeyOps []string
}

// KeyType returns the JWK "kty" string for the key: "EC", "RSA", or "OKP".
// Returns "" if the key type is unrecognized.
//
// To access the underlying Go key, use a type switch on [PublicKey.CryptoPublicKey]:
//
//	switch key := k.CryptoPublicKey.(type) {
//	case *ecdsa.PublicKey:  // kty "EC"
//	    // key is *ecdsa.PublicKey
//	case *rsa.PublicKey:    // kty "RSA"
//	    // key is *rsa.PublicKey
//	case ed25519.PublicKey: // kty "OKP"
//	    // key is ed25519.PublicKey
//	default:
//	    // unrecognized key type
//	}
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
	*k = *decoded
	return nil
}

// Thumbprint computes the RFC 7638 JWK Thumbprint (SHA-256 of the canonical
// key JSON with fields in lexicographic order). The result is base64url-encoded.
//
// https://www.rfc-editor.org/rfc/rfc7638.html
//
// Canonical forms per RFC 7638:
//   - EC:  {"crv":..., "kty":"EC", "x":..., "y":...}
//   - RSA: {"e":..., "kty":"RSA", "n":...}
//   - OKP: {"crv":"Ed25519", "kty":"OKP", "x":...}
func (k PublicKey) Thumbprint() (string, error) {
	rk, err := encode(k)
	if err != nil {
		return "", err
	}

	// Build canonical JSON with fields in lexicographic order per RFC 7638.
	var canonical []byte
	switch rk.Kty {
	case "EC":
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
			Y   string `json:"y"`
		}{Crv: rk.Crv, Kty: rk.Kty, X: rk.X, Y: rk.Y})
	case "RSA":
		canonical, err = json.Marshal(struct {
			E   string `json:"e"`
			Kty string `json:"kty"`
			N   string `json:"n"`
		}{E: rk.E, Kty: rk.Kty, N: rk.N})
	case "OKP":
		canonical, err = json.Marshal(struct {
			Crv string `json:"crv"`
			Kty string `json:"kty"`
			X   string `json:"x"`
		}{Crv: rk.Crv, Kty: rk.Kty, X: rk.X})
	default:
		return "", fmt.Errorf("thumbprint: kty %q: %w", rk.Kty, jose.ErrUnsupportedKeyType)
	}
	if err != nil {
		return "", fmt.Errorf("thumbprint: marshal canonical JSON: %w", err)
	}

	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// PrivateKey wraps a [crypto.Signer] (private key) with its JWKS metadata.
//
// PrivateKey implements [json.Marshaler] and [json.Unmarshaler]:
// marshaling includes the private key material (the "d" field and RSA primes);
// unmarshaling reconstructs a fully operational signing key from a JWK with
// private fields present. Never publish the marshaled output - it contains
// private key material.
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
// KID, Use, and Alg are copied directly. KeyOps are translated to their
// public-key equivalents: "sign"=>"verify", "decrypt"=>"encrypt",
// "unwrapKey"=>"wrapKey". Any op with no public equivalent is omitted.
//
// Returns an error if the Signer's Public() method does not return a
// known CryptoPublicKey type — this should never happen for keys created
// through this library.
func (k *PrivateKey) PublicKey() (*PublicKey, error) {
	pub, ok := k.Signer.Public().(CryptoPublicKey)
	if !ok {
		return nil, fmt.Errorf("%w: private key type %T did not produce a known public key type", jose.ErrSanityFail, k.Signer)
	}
	return &PublicKey{
		CryptoPublicKey: pub,
		KID:             k.KID,
		Use:             k.Use,
		Alg:             k.Alg,
		KeyOps:          toPublicKeyOps(k.KeyOps),
	}, nil
}

// toPublicKeyOps translates private-key key_ops values to their public-key
// counterparts per RFC 7517 §4.3. Operations with no public-key equivalent
// (e.g. "deriveKey", "deriveBits") are dropped.
func toPublicKeyOps(ops []string) []string {
	if len(ops) == 0 {
		return ops
	}
	out := make([]string, 0, len(ops))
	for _, op := range ops {
		switch op {
		case "sign":
			out = append(out, "verify")
		case "decrypt":
			out = append(out, "encrypt")
		case "unwrapKey":
			out = append(out, "wrapKey")
		case "verify", "encrypt", "wrapKey":
			// TODO if the private key had the wrong details, it probably should have been caught earlier
			// Already a public-key op - pass through.
			out = append(out, op)
		}
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// Thumbprint computes the RFC 7638 thumbprint for this key's public side.
// It delegates to [PublicKey.Thumbprint] on the result of [PrivateKey.PublicKey].
func (k *PrivateKey) Thumbprint() (string, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return "", err
	}
	return pub.Thumbprint()
}

// NewPrivateKey generates a new Ed25519 private key and returns it as a [PrivateKey].
// The KID is auto-computed from the RFC 7638 thumbprint of the public key.
//
// Ed25519 is the recommended default: fast, compact 64-byte signatures, and
// deterministic signing (no per-signature random nonce, unlike ECDSA).
// To use a different algorithm, construct [PrivateKey] directly with
// your own [crypto.Signer].
func NewPrivateKey() (*PrivateKey, error) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("NewPrivateKey: generate Ed25519 key: %w", err)
	}
	pk := &PrivateKey{Signer: priv}
	kid, err := pk.Thumbprint()
	if err != nil {
		return nil, fmt.Errorf("NewPrivateKey: compute thumbprint: %w", err)
	}
	pk.KID = kid
	return pk, nil
}

// MarshalJSON implements [json.Marshaler], encoding the key as a JWK JSON object
// that includes private key material (the "d" field and RSA CRT components).
// Never publish the result - it contains the private key.
func (k PrivateKey) MarshalJSON() ([]byte, error) {
	pk, err := encodePrivate(k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(pk)
}

// UnmarshalJSON implements [json.Unmarshaler], parsing a JWK JSON object that
// contains private key material. The "d" field (and RSA primes) must be present;
// public-key-only JWKs return an error. If the JWK has no "kid" field, the KID
// is auto-computed via [PublicKey.Thumbprint].
func (k *PrivateKey) UnmarshalJSON(data []byte) error {
	var kj rawKey
	if err := json.Unmarshal(data, &kj); err != nil {
		return fmt.Errorf("parse JWK: %w", err)
	}
	decoded, err := decodePrivate(kj)
	if err != nil {
		return err
	}
	*k = *decoded
	return nil
}

// rawKey is the unexported JSON wire representation of a JWK object.
// It is used internally by [PublicKey] and [PrivateKey] JSON methods.
type rawKey struct {
	Kty    string   `json:"kty"`
	KID    string   `json:"kid,omitempty"`
	Crv    string   `json:"crv,omitempty"`
	X      string   `json:"x,omitempty"`
	Y      string   `json:"y,omitempty"`
	D      string   `json:"d,omitempty"` // EC/OKP: private scalar; RSA: private exponent
	N      string   `json:"n,omitempty"`
	E      string   `json:"e,omitempty"`
	P      string   `json:"p,omitempty"`  // RSA: first prime factor
	Q      string   `json:"q,omitempty"`  // RSA: second prime factor
	DP     string   `json:"dp,omitempty"` // RSA: d mod (p-1)
	DQ     string   `json:"dq,omitempty"` // RSA: d mod (q-1)
	QI     string   `json:"qi,omitempty"` // RSA: q^-1 mod p
	Use    string   `json:"use,omitempty"`
	Alg    string   `json:"alg,omitempty"`
	KeyOps []string `json:"key_ops,omitempty"`
}

// JWKs is a JSON Web Key Set. Use json.Marshal and json.Unmarshal directly -
// each [PublicKey] in Keys handles its own encoding via MarshalJSON / UnmarshalJSON.
type JWKs struct {
	Keys []PublicKey `json:"keys"`
}

// encode converts a [PublicKey] to its [rawKey] wire representation.
// Used by [PublicKey.MarshalJSON] and [PublicKey.Thumbprint].
func encode(k PublicKey) (rawKey, error) {
	rk := rawKey{KID: k.KID, Use: k.Use, Alg: k.Alg, KeyOps: k.KeyOps}

	switch key := k.CryptoPublicKey.(type) {
	case *ecdsa.PublicKey:
		ci, err := jwa.ECInfo(key.Curve)
		if err != nil {
			return rawKey{}, err
		}
		b, err := key.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return rawKey{}, fmt.Errorf("encode EC key: %w", err)
		}
		rk.Kty = "EC"
		rk.Crv = ci.Crv
		rk.X = base64.RawURLEncoding.EncodeToString(b[1 : 1+ci.KeySize])
		rk.Y = base64.RawURLEncoding.EncodeToString(b[1+ci.KeySize:])
		return rk, nil

	case *rsa.PublicKey:
		eInt := big.NewInt(int64(key.E))
		rk.Kty = "RSA"
		rk.N = base64.RawURLEncoding.EncodeToString(key.N.Bytes())
		rk.E = base64.RawURLEncoding.EncodeToString(eInt.Bytes())
		return rk, nil

	case ed25519.PublicKey:
		rk.Kty = "OKP"
		rk.Crv = "Ed25519"
		rk.X = base64.RawURLEncoding.EncodeToString([]byte(key))
		return rk, nil

	default:
		return rawKey{}, fmt.Errorf("%T: %w", k.CryptoPublicKey, jose.ErrUnsupportedKeyType)
	}
}

// encodePrivate converts a [PrivateKey] to its [rawKey] wire representation,
// including private key material (d, and RSA CRT components p/q/dp/dq/qi).
// Used by [PrivateKey.MarshalJSON].
func encodePrivate(k PrivateKey) (rawKey, error) {
	pub, err := k.PublicKey()
	if err != nil {
		return rawKey{}, err
	}
	rk, err := encode(*pub)
	if err != nil {
		return rawKey{}, err
	}

	switch priv := k.Signer.(type) {
	case *ecdsa.PrivateKey:
		dBytes, err := priv.Bytes()
		if err != nil {
			return rawKey{}, fmt.Errorf("encode EC private key: %w", err)
		}
		rk.D = base64.RawURLEncoding.EncodeToString(dBytes)

	case *rsa.PrivateKey:
		rk.D = base64.RawURLEncoding.EncodeToString(priv.D.Bytes())
		if len(priv.Primes) >= 2 {
			priv.Precompute()
			rk.P = base64.RawURLEncoding.EncodeToString(priv.Primes[0].Bytes())
			rk.Q = base64.RawURLEncoding.EncodeToString(priv.Primes[1].Bytes())
			if priv.Precomputed.Dp != nil {
				rk.DP = base64.RawURLEncoding.EncodeToString(priv.Precomputed.Dp.Bytes())
				rk.DQ = base64.RawURLEncoding.EncodeToString(priv.Precomputed.Dq.Bytes())
				rk.QI = base64.RawURLEncoding.EncodeToString(priv.Precomputed.Qinv.Bytes())
			}
		}

	case ed25519.PrivateKey:
		rk.D = base64.RawURLEncoding.EncodeToString(priv.Seed())

	default:
		return rawKey{}, fmt.Errorf("%T: %w", k.Signer, jose.ErrUnsupportedKeyType)
	}

	return rk, nil
}

// ReadFile reads and parses a JWKS document from a file path.
// It is equivalent to os.ReadFile followed by json.Unmarshal into a [JWKs].
func ReadFile(filePath string) ([]PublicKey, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, fmt.Errorf("read JWKS file %q: %w", filePath, err)
	}
	var jwks JWKs
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("parse JWKS file %q: %w", filePath, err)
	}
	return jwks.Keys, nil
}

// decodeOne parses a single rawKey wire struct into a [PublicKey].
// If the JWK has no "kid" field, the KID is auto-computed via [PublicKey.Thumbprint].
//
// Supported key types:
//   - "RSA" - minimum 1024-bit (RS256)
//   - "EC"  - P-256, P-384, P-521 (ES256, ES384, ES512)
//   - "OKP" - Ed25519 crv (EdDSA, RFC 8037) https://www.rfc-editor.org/rfc/rfc8037.html
func decodeOne(kj rawKey) (*PublicKey, error) {
	var pk *PublicKey
	switch kj.Kty {
	case "RSA":
		key, err := decodeRSA(kj)
		if err != nil {
			return nil, fmt.Errorf("parse RSA key %q: %w", kj.KID, err)
		}
		pk = kj.newPublicKey(key)

	case "EC":
		key, err := decodeEC(kj)
		if err != nil {
			return nil, fmt.Errorf("parse EC key %q: %w", kj.KID, err)
		}
		pk = kj.newPublicKey(key)

	case "OKP":
		key, err := decodeOKP(kj)
		if err != nil {
			return nil, fmt.Errorf("parse OKP key %q: %w", kj.KID, err)
		}
		pk = kj.newPublicKey(key)

	default:
		return nil, fmt.Errorf("kid %q: kty %q: %w", kj.KID, kj.Kty, jose.ErrUnsupportedKeyType)
	}

	if pk.KID == "" {
		kid, err := pk.Thumbprint()
		if err != nil {
			return nil, fmt.Errorf("compute thumbprint: %w", err)
		}
		pk.KID = kid
	}
	return pk, nil
}

// decodePrivate parses a rawKey wire struct that contains private key material
// into a [PrivateKey]. If the JWK has no "kid" field, the KID is auto-computed
// via [PublicKey.Thumbprint]. Returns an error if the "d" field is missing.
func decodePrivate(kj rawKey) (*PrivateKey, error) {
	if kj.D == "" {
		return nil, fmt.Errorf("\"d\" field missing: %w", jose.ErrMissingKeyData)
	}

	var pk *PrivateKey
	switch kj.Kty {
	case "EC":
		ci, err := jwa.ECInfoByCrv(kj.Crv)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key %q: %w", kj.KID, err)
		}
		dBytes, err := decodeB64Field("EC", kj.KID, "d", kj.D)
		if err != nil {
			return nil, err
		}
		// ParseRawPrivateKey validates the scalar and derives the public key.
		priv, err := ecdsa.ParseRawPrivateKey(ci.Curve, dBytes)
		if err != nil {
			return nil, fmt.Errorf("parse EC private key %q: %w: %w", kj.KID, jose.ErrInvalidKey, err)
		}
		pk = kj.newPrivateKey(priv)

	case "RSA":
		pub, err := decodeRSA(kj)
		if err != nil {
			return nil, fmt.Errorf("parse RSA private key %q: %w", kj.KID, err)
		}
		dBytes, err := decodeB64Field("RSA", kj.KID, "d", kj.D)
		if err != nil {
			return nil, err
		}
		priv := &rsa.PrivateKey{
			PublicKey: *pub,
			D:         new(big.Int).SetBytes(dBytes),
		}
		if kj.P != "" && kj.Q != "" {
			p, err := decodeB64Field("RSA", kj.KID, "p", kj.P)
			if err != nil {
				return nil, err
			}
			q, err := decodeB64Field("RSA", kj.KID, "q", kj.Q)
			if err != nil {
				return nil, err
			}
			priv.Primes = []*big.Int{
				new(big.Int).SetBytes(p),
				new(big.Int).SetBytes(q),
			}
			priv.Precompute()
		}
		if err := priv.Validate(); err != nil {
			return nil, fmt.Errorf("parse RSA private key %q: %w: %w", kj.KID, jose.ErrInvalidKey, err)
		}
		pk = kj.newPrivateKey(priv)

	case "OKP":
		if kj.Crv != "Ed25519" {
			return nil, fmt.Errorf("parse OKP private key %q: crv %q: %w", kj.KID, kj.Crv, jose.ErrUnsupportedCurve)
		}
		seed, err := decodeB64Field("Ed25519", kj.KID, "d", kj.D)
		if err != nil {
			return nil, err
		}
		if len(seed) != ed25519.SeedSize {
			return nil, fmt.Errorf("parse Ed25519 private key %q: seed size %d, want %d: %w", kj.KID, len(seed), ed25519.SeedSize, jose.ErrInvalidKey)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pk = kj.newPrivateKey(priv)

	default:
		return nil, fmt.Errorf("kid %q: kty %q: %w", kj.KID, kj.Kty, jose.ErrUnsupportedKeyType)
	}

	if pk.KID == "" {
		kid, err := pk.Thumbprint()
		if err != nil {
			return nil, fmt.Errorf("compute thumbprint: %w", err)
		}
		pk.KID = kid
	}
	return pk, nil
}

// newPublicKey creates a [PublicKey] from a crypto key, copying metadata
// (KID, Use, Alg, KeyOps) from the rawKey.
func (kj rawKey) newPublicKey(key CryptoPublicKey) *PublicKey {
	return &PublicKey{CryptoPublicKey: key, KID: kj.KID, Use: kj.Use, Alg: kj.Alg, KeyOps: kj.KeyOps}
}

// newPrivateKey creates a [PrivateKey] from a crypto.Signer, copying metadata
// (KID, Use, Alg, KeyOps) from the rawKey.
func (kj rawKey) newPrivateKey(signer crypto.Signer) *PrivateKey {
	return &PrivateKey{Signer: signer, KID: kj.KID, Use: kj.Use, Alg: kj.Alg, KeyOps: kj.KeyOps}
}

// decodeB64Field decodes a base64url-encoded JWK field value, returning a
// descriptive error that includes the key type, KID, and field name.
func decodeB64Field(kty, kid, field, value string) ([]byte, error) {
	b, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("parse %s private key %q: invalid %s: %w: %w", kty, kid, field, jose.ErrInvalidKey, err)
	}
	return b, nil
}

func decodeRSA(kj rawKey) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(kj.N)
	if err != nil {
		return nil, fmt.Errorf("invalid n: %w: %w", jose.ErrInvalidKey, err)
	}
	e, err := base64.RawURLEncoding.DecodeString(kj.E)
	if err != nil {
		return nil, fmt.Errorf("invalid e: %w: %w", jose.ErrInvalidKey, err)
	}

	eInt := new(big.Int).SetBytes(e)
	if !eInt.IsInt64() {
		return nil, fmt.Errorf("RSA exponent too large: %w", jose.ErrInvalidKey)
	}
	eVal := eInt.Int64()
	// Minimum exponent of 3 rejects degenerate keys (e=1 makes RSA trivial).
	// Cap at MaxInt32 so the value fits in an int on 32-bit platforms.
	if eVal < 3 {
		return nil, fmt.Errorf("RSA exponent must be at least 3, got %d: %w", eVal, jose.ErrInvalidKey)
	}
	if eVal > 1<<31-1 {
		return nil, fmt.Errorf("RSA exponent too large for 32-bit platforms: %d: %w", eVal, jose.ErrInvalidKey)
	}

	key := &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(eVal),
	}
	// 1024-bit minimum: lower than the 2048-bit industry recommendation,
	// but allows real-world compatibility with older keys and is useful
	// for testing. Production deployments should use 2048+ bits.
	if key.Size() < 128 { // 1024 bits minimum
		return nil, fmt.Errorf("%d bits: %w", key.Size()*8, jose.ErrKeyTooSmall)
	}
	return key, nil
}

func decodeEC(kj rawKey) (*ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(kj.X)
	if err != nil {
		return nil, fmt.Errorf("invalid x: %w: %w", jose.ErrInvalidKey, err)
	}
	y, err := base64.RawURLEncoding.DecodeString(kj.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid y: %w: %w", jose.ErrInvalidKey, err)
	}

	ci, err := jwa.ECInfoByCrv(kj.Crv)
	if err != nil {
		return nil, err
	}

	// Build the uncompressed point (0x04 || X || Y), left-padding each
	// coordinate to the expected byte length. ParseUncompressedPublicKey
	// validates that the point is on the curve.
	if len(x) > ci.KeySize {
		return nil, fmt.Errorf("x coordinate too long for %s: got %d bytes, want %d: %w", kj.Crv, len(x), ci.KeySize, jose.ErrInvalidKey)
	}
	if len(y) > ci.KeySize {
		return nil, fmt.Errorf("y coordinate too long for %s: got %d bytes, want %d: %w", kj.Crv, len(y), ci.KeySize, jose.ErrInvalidKey)
	}
	uncompressed := make([]byte, 1+2*ci.KeySize)
	uncompressed[0] = 0x04
	copy(uncompressed[1+ci.KeySize-len(x):1+ci.KeySize], x) // left-pad X
	copy(uncompressed[1+2*ci.KeySize-len(y):], y)            // left-pad Y
	key, err := ecdsa.ParseUncompressedPublicKey(ci.Curve, uncompressed)
	if err != nil {
		return nil, fmt.Errorf("EC point not on curve %s: %w: %w", kj.Crv, jose.ErrInvalidKey, err)
	}
	return key, nil
}

func decodeOKP(kj rawKey) (ed25519.PublicKey, error) {
	if kj.Crv != "Ed25519" {
		return nil, fmt.Errorf("crv %q (only Ed25519 supported): %w", kj.Crv, jose.ErrUnsupportedCurve)
	}
	x, err := base64.RawURLEncoding.DecodeString(kj.X)
	if err != nil {
		return nil, fmt.Errorf("invalid x: %w: %w", jose.ErrInvalidKey, err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("Ed25519 key size %d bytes, want %d: %w", len(x), ed25519.PublicKeySize, jose.ErrInvalidKey)
	}
	return ed25519.PublicKey(x), nil
}
