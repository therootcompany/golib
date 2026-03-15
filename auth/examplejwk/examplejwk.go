// Package examplejwk demonstrates JWK (JSON Web Key) encoding and decoding for
// RSA, EC (P-256/P-384/P-521), and OKP (Ed25519) keys.
//
// PublicKey and PrivateKey are the rich in-memory types that hold actual Go
// crypto keys. They implement json.Marshaler and json.Unmarshaler via unexported
// intermediary structs (publicJWK and privateJWK), which carry the raw
// base64url-encoded wire fields. The intermediary types are not part of the
// public API — callers only ever see PublicKey and PrivateKey.
package examplejwk

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
)

// publicJWK is the unexported JSON wire representation of a JWK public key.
// All key-type-specific fields are flat in one struct; fields irrelevant to a
// given key type are left empty and omitted from JSON output via omitempty.
type publicJWK struct {
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

// privateJWK is the unexported JSON wire representation of a JWK private key.
// It embeds publicJWK and adds d plus the RSA CRT parameters.
type privateJWK struct {
	publicJWK
	D  string `json:"d,omitempty"`
	P  string `json:"p,omitempty"`
	Q  string `json:"q,omitempty"`
	Dp string `json:"dp,omitempty"`
	Dq string `json:"dq,omitempty"`
	Qi string `json:"qi,omitempty"`
}

// PublicKey holds a decoded JWK public key (RSA, EC, or OKP/Ed25519) together
// with its JWKS metadata. json.Marshal and json.Unmarshal work directly on
// this type — there are no exported wire types to deal with.
type PublicKey struct {
	Key    crypto.PublicKey // *rsa.PublicKey | *ecdsa.PublicKey | ed25519.PublicKey
	KID    string
	Use    string
	Alg    string
	KeyOps []string
}

// PrivateKey holds a decoded JWK private key (RSA, EC, or OKP/Ed25519) together
// with its JWKS metadata. json.Marshal and json.Unmarshal work directly on
// this type — there are no exported wire types to deal with.
type PrivateKey struct {
	Key    crypto.Signer // *rsa.PrivateKey | *ecdsa.PrivateKey | ed25519.PrivateKey
	KID    string
	Use    string
	Alg    string
	KeyOps []string
}

// MarshalJSON implements json.Marshaler.
func (k PublicKey) MarshalJSON() ([]byte, error) {
	wire, err := encodePublicKey(k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wire)
}

// UnmarshalJSON implements json.Unmarshaler.
func (k *PublicKey) UnmarshalJSON(data []byte) error {
	var wire publicJWK
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("examplejwk: parse public JWK: %w", err)
	}
	return decodePublicKey(wire, k)
}

// MarshalJSON implements json.Marshaler.
func (k PrivateKey) MarshalJSON() ([]byte, error) {
	wire, err := encodePrivateKey(k)
	if err != nil {
		return nil, err
	}
	return json.Marshal(wire)
}

// UnmarshalJSON implements json.Unmarshaler.
func (k *PrivateKey) UnmarshalJSON(data []byte) error {
	var wire privateJWK
	if err := json.Unmarshal(data, &wire); err != nil {
		return fmt.Errorf("examplejwk: parse private JWK: %w", err)
	}
	return decodePrivateKey(wire, k)
}

// --- encode: rich type → wire struct ---

func encodePublicKey(k PublicKey) (publicJWK, error) {
	wire := publicJWK{
		KID:    k.KID,
		Use:    k.Use,
		Alg:    k.Alg,
		KeyOps: k.KeyOps,
	}

	switch key := k.Key.(type) {
	case *ecdsa.PublicKey:
		crv, err := curveName(key.Curve)
		if err != nil {
			return publicJWK{}, fmt.Errorf("examplejwk: encode: %w", err)
		}
		b, err := key.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return publicJWK{}, fmt.Errorf("examplejwk: encode EC key: %w", err)
		}
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		wire.Kty = "EC"
		wire.Crv = crv
		wire.X = b64url(b[1 : 1+byteLen])
		wire.Y = b64url(b[1+byteLen:])

	case *rsa.PublicKey:
		wire.Kty = "RSA"
		wire.N = b64url(key.N.Bytes())
		wire.E = b64url(big.NewInt(int64(key.E)).Bytes())

	case ed25519.PublicKey:
		wire.Kty = "OKP"
		wire.Crv = "Ed25519"
		wire.X = b64url([]byte(key))

	default:
		return publicJWK{}, fmt.Errorf("examplejwk: encode: unsupported key type %T", k.Key)
	}

	return wire, nil
}

func encodePrivateKey(k PrivateKey) (privateJWK, error) {
	wire := privateJWK{}
	wire.KID = k.KID
	wire.Use = k.Use
	wire.Alg = k.Alg
	wire.KeyOps = k.KeyOps

	switch key := k.Key.(type) {
	case *ecdsa.PrivateKey:
		crv, err := curveName(key.Curve)
		if err != nil {
			return privateJWK{}, fmt.Errorf("examplejwk: encode: %w", err)
		}
		b, err := key.PublicKey.Bytes() // uncompressed: 0x04 || X || Y
		if err != nil {
			return privateJWK{}, fmt.Errorf("examplejwk: encode EC public key: %w", err)
		}
		byteLen := (key.Curve.Params().BitSize + 7) / 8
		// Use ECDH conversion to read the private scalar bytes without going
		// through the deprecated key.D big.Int field.
		ecdhKey, err := key.ECDH()
		if err != nil {
			return privateJWK{}, fmt.Errorf("examplejwk: encode EC private key: %w", err)
		}
		wire.Kty = "EC"
		wire.Crv = crv
		wire.X = b64url(b[1 : 1+byteLen])
		wire.Y = b64url(b[1+byteLen:])
		wire.D = b64url(ecdhKey.Bytes())

	case *rsa.PrivateKey:
		wire.Kty = "RSA"
		wire.N = b64url(key.PublicKey.N.Bytes())
		wire.E = b64url(big.NewInt(int64(key.PublicKey.E)).Bytes())
		wire.D = b64url(key.D.Bytes())
		if len(key.Primes) >= 2 {
			wire.P = b64url(key.Primes[0].Bytes())
			wire.Q = b64url(key.Primes[1].Bytes())
		}
		if key.Precomputed.Dp != nil {
			wire.Dp = b64url(key.Precomputed.Dp.Bytes())
		}
		if key.Precomputed.Dq != nil {
			wire.Dq = b64url(key.Precomputed.Dq.Bytes())
		}
		if key.Precomputed.Qinv != nil {
			wire.Qi = b64url(key.Precomputed.Qinv.Bytes())
		}

	case ed25519.PrivateKey:
		// ed25519.PrivateKey layout: seed (32 bytes) || public key (32 bytes)
		wire.Kty = "OKP"
		wire.Crv = "Ed25519"
		wire.X = b64url([]byte(key[ed25519.SeedSize:]))
		wire.D = b64url([]byte(key[:ed25519.SeedSize]))

	default:
		return privateJWK{}, fmt.Errorf("examplejwk: encode: unsupported key type %T", k.Key)
	}

	return wire, nil
}

// --- decode: wire struct → rich type ---

func decodePublicKey(wire publicJWK, k *PublicKey) error {
	k.KID = wire.KID
	k.Use = wire.Use
	k.Alg = wire.Alg
	k.KeyOps = wire.KeyOps

	switch wire.Kty {
	case "EC":
		key, err := decodeECPublic(wire)
		if err != nil {
			return fmt.Errorf("examplejwk: decode EC key: %w", err)
		}
		k.Key = key

	case "RSA":
		key, err := decodeRSAPublic(wire)
		if err != nil {
			return fmt.Errorf("examplejwk: decode RSA key: %w", err)
		}
		k.Key = key

	case "OKP":
		key, err := decodeOKPPublic(wire)
		if err != nil {
			return fmt.Errorf("examplejwk: decode OKP key: %w", err)
		}
		k.Key = key

	default:
		return fmt.Errorf("examplejwk: decode: unsupported kty %q", wire.Kty)
	}

	return nil
}

func decodePrivateKey(wire privateJWK, k *PrivateKey) error {
	k.KID = wire.KID
	k.Use = wire.Use
	k.Alg = wire.Alg
	k.KeyOps = wire.KeyOps

	switch wire.Kty {
	case "EC":
		key, err := decodeECPrivate(wire)
		if err != nil {
			return fmt.Errorf("examplejwk: decode EC key: %w", err)
		}
		k.Key = key

	case "RSA":
		key, err := decodeRSAPrivate(wire)
		if err != nil {
			return fmt.Errorf("examplejwk: decode RSA key: %w", err)
		}
		k.Key = key

	case "OKP":
		key, err := decodeOKPPrivate(wire)
		if err != nil {
			return fmt.Errorf("examplejwk: decode OKP key: %w", err)
		}
		k.Key = key

	default:
		return fmt.Errorf("examplejwk: decode: unsupported kty %q", wire.Kty)
	}

	return nil
}

func decodeECPublic(wire publicJWK) (*ecdsa.PublicKey, error) {
	curve, err := parseCurve(wire.Crv)
	if err != nil {
		return nil, err
	}
	x, err := b64decode(wire.X)
	if err != nil {
		return nil, fmt.Errorf("invalid x: %w", err)
	}
	y, err := b64decode(wire.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid y: %w", err)
	}
	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}

func decodeECPrivate(wire privateJWK) (*ecdsa.PrivateKey, error) {
	pub, err := decodeECPublic(wire.publicJWK)
	if err != nil {
		return nil, err
	}
	d, err := b64decode(wire.D)
	if err != nil {
		return nil, fmt.Errorf("invalid d: %w", err)
	}
	return &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(d),
	}, nil
}

func decodeRSAPublic(wire publicJWK) (*rsa.PublicKey, error) {
	n, err := b64decode(wire.N)
	if err != nil {
		return nil, fmt.Errorf("invalid n: %w", err)
	}
	e, err := b64decode(wire.E)
	if err != nil {
		return nil, fmt.Errorf("invalid e: %w", err)
	}
	eInt := new(big.Int).SetBytes(e)
	if !eInt.IsInt64() {
		return nil, fmt.Errorf("RSA exponent too large")
	}
	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(eInt.Int64()),
	}, nil
}

func decodeRSAPrivate(wire privateJWK) (*rsa.PrivateKey, error) {
	pub, err := decodeRSAPublic(wire.publicJWK)
	if err != nil {
		return nil, err
	}
	d, err := b64decode(wire.D)
	if err != nil {
		return nil, fmt.Errorf("invalid d: %w", err)
	}

	priv := &rsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(d),
	}

	if wire.P != "" && wire.Q != "" {
		p, err := b64decode(wire.P)
		if err != nil {
			return nil, fmt.Errorf("invalid p: %w", err)
		}
		q, err := b64decode(wire.Q)
		if err != nil {
			return nil, fmt.Errorf("invalid q: %w", err)
		}
		priv.Primes = []*big.Int{
			new(big.Int).SetBytes(p),
			new(big.Int).SetBytes(q),
		}
	}
	if wire.Dp != "" {
		dp, err := b64decode(wire.Dp)
		if err != nil {
			return nil, fmt.Errorf("invalid dp: %w", err)
		}
		priv.Precomputed.Dp = new(big.Int).SetBytes(dp)
	}
	if wire.Dq != "" {
		dq, err := b64decode(wire.Dq)
		if err != nil {
			return nil, fmt.Errorf("invalid dq: %w", err)
		}
		priv.Precomputed.Dq = new(big.Int).SetBytes(dq)
	}
	if wire.Qi != "" {
		qi, err := b64decode(wire.Qi)
		if err != nil {
			return nil, fmt.Errorf("invalid qi: %w", err)
		}
		priv.Precomputed.Qinv = new(big.Int).SetBytes(qi)
	}

	return priv, nil
}

func decodeOKPPublic(wire publicJWK) (ed25519.PublicKey, error) {
	if wire.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve %q (only Ed25519 supported)", wire.Crv)
	}
	x, err := b64decode(wire.X)
	if err != nil {
		return nil, fmt.Errorf("invalid x: %w", err)
	}
	if len(x) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("invalid Ed25519 public key size: got %d, want %d", len(x), ed25519.PublicKeySize)
	}
	return ed25519.PublicKey(x), nil
}

func decodeOKPPrivate(wire privateJWK) (ed25519.PrivateKey, error) {
	if wire.Crv != "Ed25519" {
		return nil, fmt.Errorf("unsupported OKP curve %q (only Ed25519 supported)", wire.Crv)
	}
	seed, err := b64decode(wire.D)
	if err != nil {
		return nil, fmt.Errorf("invalid d: %w", err)
	}
	if len(seed) != ed25519.SeedSize {
		return nil, fmt.Errorf("invalid Ed25519 seed size: got %d, want %d", len(seed), ed25519.SeedSize)
	}
	return ed25519.NewKeyFromSeed(seed), nil
}

// --- helpers ---

func curveName(curve elliptic.Curve) (string, error) {
	switch curve {
	case elliptic.P256():
		return "P-256", nil
	case elliptic.P384():
		return "P-384", nil
	case elliptic.P521():
		return "P-521", nil
	default:
		return "", fmt.Errorf("unsupported EC curve %s", curve.Params().Name)
	}
}

func parseCurve(crv string) (elliptic.Curve, error) {
	switch crv {
	case "P-256":
		return elliptic.P256(), nil
	case "P-384":
		return elliptic.P384(), nil
	case "P-521":
		return elliptic.P521(), nil
	default:
		return nil, fmt.Errorf("unsupported EC curve %q", crv)
	}
}

func b64url(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func b64decode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}
