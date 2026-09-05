// Package testkeys provides shared key generation and test helpers for the
// JWT/JWS/JWK interop test suite. It is a regular (non-test) package so that
// each test subdirectory can import it.
package testkeys

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"io"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// TestClaims returns a fresh TokenClaims with iss, sub, exp, and iat set.
func TestClaims(sub string) *jwt.TokenClaims {
	now := time.Now()
	return &jwt.TokenClaims{
		Iss: "https://example.com",
		Sub: sub,
		Exp: now.Add(time.Hour).Unix(),
		IAt: now.Unix(),
	}
}

// ListishClaims returns claims with the given audience.
func ListishClaims(sub string, aud jwt.Listish) *jwt.TokenClaims {
	c := TestClaims(sub)
	c.Aud = aud
	return c
}

// CustomClaims embeds TokenClaims and adds extra fields for testing
// cross-library custom claims extraction.
type CustomClaims struct {
	jwt.TokenClaims
	Email    string            `json:"email"`
	Roles    []string          `json:"roles"`
	Metadata map[string]string `json:"metadata,omitempty"`
}

// DeterministicRand returns a deterministic io.Reader seeded from a string.
// Not cryptographically secure - used only for reproducible test key generation.
func DeterministicRand(seed string) io.Reader {
	s := sha256.Sum256([]byte(seed))
	return &hashReader{state: s}
}

type hashReader struct {
	state [32]byte
	pos   int
}

func (r *hashReader) Read(p []byte) (int, error) {
	n := 0
	for n < len(p) {
		if r.pos >= len(r.state) {
			r.state = sha256.Sum256(r.state[:])
			r.pos = 0
		}
		copied := copy(p[n:], r.state[r.pos:])
		n += copied
		r.pos += copied
	}
	return n, nil
}

// KeySet bundles a generated key in all the forms interop tests need:
// our library's wrappers, the raw Go crypto types, and metadata.
type KeySet struct {
	PrivKey *jwt.PrivateKey // our library's key wrapper
	PubKey  jwt.PublicKey   // our library's public key wrapper
	RawPriv any             // *ecdsa.PrivateKey | *rsa.PrivateKey | ed25519.PrivateKey
	RawPub  any             // *ecdsa.PublicKey | *rsa.PublicKey | ed25519.PublicKey
	KID     string
	AlgName string // "EdDSA", "ES256", "ES384", "ES512", "RS256"
}

func mustPK(signer crypto.Signer, kid string) *jwt.PrivateKey {
	pk, err := jwt.FromPrivateKey(signer, kid)
	if err != nil {
		panic("mustPK: " + err.Error())
	}
	return pk
}

// GenerateEdDSA generates an Ed25519 key set.
func GenerateEdDSA(kid string) KeySet {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		panic("GenerateEdDSA: " + err.Error())
	}
	pub := priv.Public().(ed25519.PublicKey)
	return KeySet{
		PrivKey: mustPK(priv, kid),
		PubKey:  jwt.PublicKey{Pub: pub, KID: kid},
		RawPriv: priv, RawPub: pub,
		KID: kid, AlgName: "EdDSA",
	}
}

// GenerateES256 generates an EC P-256 key set.
func GenerateES256(kid string) KeySet { return generateEC(kid, elliptic.P256(), "ES256") }

// GenerateES384 generates an EC P-384 key set.
func GenerateES384(kid string) KeySet { return generateEC(kid, elliptic.P384(), "ES384") }

// GenerateES512 generates an EC P-521 key set.
func GenerateES512(kid string) KeySet { return generateEC(kid, elliptic.P521(), "ES512") }

func generateEC(kid string, curve elliptic.Curve, alg string) KeySet {
	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		panic("generateEC " + alg + ": " + err.Error())
	}
	return KeySet{
		PrivKey: mustPK(priv, kid),
		PubKey:  jwt.PublicKey{Pub: &priv.PublicKey, KID: kid},
		RawPriv: priv, RawPub: &priv.PublicKey,
		KID: kid, AlgName: alg,
	}
}

// GenerateRS256 generates an RSA 2048-bit key set.
func GenerateRS256(kid string) KeySet {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		panic("GenerateRS256: " + err.Error())
	}
	return KeySet{
		PrivKey: mustPK(priv, kid),
		PubKey:  jwt.PublicKey{Pub: &priv.PublicKey, KID: kid},
		RawPriv: priv, RawPub: &priv.PublicKey,
		KID: kid, AlgName: "RS256",
	}
}

// AlgGen pairs an algorithm name with its key generator.
type AlgGen struct {
	Name     string
	Generate func(kid string) KeySet
}

// AllAlgorithms returns generators for all 5 supported algorithms.
func AllAlgorithms() []AlgGen {
	return []AlgGen{
		{"EdDSA", GenerateEdDSA},
		{"ES256", GenerateES256},
		{"ES384", GenerateES384},
		{"ES512", GenerateES512},
		{"RS256", GenerateRS256},
	}
}
