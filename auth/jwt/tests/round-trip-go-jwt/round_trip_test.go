// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package roundtrip_test verifies interoperability between this library and
// github.com/golang-jwt/jwt/v5. It lives in a separate module (tests/go.mod)
// so that the golang-jwt dependency does not leak into the main module graph.
//
// Tests cover:
//   - Our sign + their verify (Ed25519, EC P-256, P-384, P-521, RSA)
//   - Their sign + our verify (Ed25519, EC P-256, P-384, P-521, RSA)
//   - Known/fixed keys: deterministic key material for reproducible tests
//   - Stress tests: 1,000 keys per algorithm to catch ASN.1/padding edge cases
//   - JWK key round-trip: marshal/unmarshal private and public keys, then
//     confirm the recovered keys interoperate correctly.
package roundtrip_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// --- helpers ---

// testClaims returns a fresh set of claims for a test iteration.
func testClaims(sub string) *jwt.IDTokenClaims {
	now := time.Now()
	return &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: sub,
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
	}
}

// hashReader produces deterministic bytes from a SHA-256 hash chain.
// Not cryptographically secure - used only for reproducible test key generation.
type hashReader struct {
	state [32]byte
	pos   int
}

func deterministicRand(seed string) io.Reader {
	s := sha256.Sum256([]byte(seed))
	return &hashReader{state: s}
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

// assertOurSignTheirVerify signs with our library and verifies with golang-jwt.
func assertOurSignTheirVerify(t *testing.T, pk jwk.PrivateKey, gjwtMethod gjwt.SigningMethod, gjwtPub any, sub string) {
	t.Helper()

	signer, err := jwt.NewSigner([]jwk.PrivateKey{pk})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	claims := testClaims(sub)
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	parsed, err := gjwt.ParseWithClaims(tokenStr, &gjwt.RegisteredClaims{}, func(tok *gjwt.Token) (any, error) {
		if tok.Method.Alg() != gjwtMethod.Alg() {
			return nil, fmt.Errorf("unexpected alg: got %q, want %q", tok.Method.Alg(), gjwtMethod.Alg())
		}
		return gjwtPub, nil
	})
	if err != nil {
		t.Fatalf("golang-jwt verify failed: %v", err)
	}
	rc, ok := parsed.Claims.(*gjwt.RegisteredClaims)
	if !ok || !parsed.Valid {
		t.Fatal("token invalid or claims unreadable")
	}
	if rc.Subject != sub {
		t.Errorf("sub: got %q, want %q", rc.Subject, sub)
	}
	if rc.Issuer != claims.Iss {
		t.Errorf("iss: got %q, want %q", rc.Issuer, claims.Iss)
	}
}

// assertTheirSignOurVerify signs with golang-jwt and verifies with our library.
func assertTheirSignOurVerify(t *testing.T, gjwtMethod gjwt.SigningMethod, gjwtPriv any, kid string, ourPub jwk.PublicKey, sub string) {
	t.Helper()

	now := time.Now()
	gClaims := gjwt.RegisteredClaims{
		Issuer:    "https://example.com",
		Subject:   sub,
		ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  gjwt.NewNumericDate(now),
	}
	tok := gjwt.NewWithClaims(gjwtMethod, gClaims)
	tok.Header["kid"] = kid

	tokenStr, err := tok.SignedString(gjwtPriv)
	if err != nil {
		t.Fatalf("golang-jwt sign: %v", err)
	}

	verifier := jwt.New([]jwk.PublicKey{ourPub})
	jws, err := verifier.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("our verify failed: %v", err)
	}

	var decoded jwt.IDTokenClaims
	if err := jwt.UnmarshalClaims(jws, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}
	if decoded.Sub != sub {
		t.Errorf("sub: got %q, want %q", decoded.Sub, sub)
	}
	if decoded.Iss != gClaims.Issuer {
		t.Errorf("iss: got %q, want %q", decoded.Iss, gClaims.Issuer)
	}
}

// stressIteration tests one key in both directions: our sign + their verify,
// then their sign + our verify.
func stressIteration(t *testing.T, i int, pk jwk.PrivateKey, pub jwk.PublicKey, gjwtMethod gjwt.SigningMethod, gjwtPriv any, gjwtPub any) {
	t.Helper()
	sub := fmt.Sprintf("stress-%d", i)

	// Our sign, their verify.
	signer, err := jwt.NewSigner([]jwk.PrivateKey{pk})
	if err != nil {
		t.Fatalf("iter %d: NewSigner: %v", i, err)
	}
	tokenStr, err := signer.SignToString(testClaims(sub))
	if err != nil {
		t.Fatalf("iter %d: SignToString: %v", i, err)
	}
	_, err = gjwt.ParseWithClaims(tokenStr, &gjwt.RegisteredClaims{}, func(tok *gjwt.Token) (any, error) {
		return gjwtPub, nil
	})
	if err != nil {
		t.Fatalf("iter %d: golang-jwt verify: %v", i, err)
	}

	// Their sign, our verify.
	gClaims := gjwt.RegisteredClaims{
		Subject:   sub,
		ExpiresAt: gjwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	tok := gjwt.NewWithClaims(gjwtMethod, gClaims)
	tok.Header["kid"] = pk.KID
	tokenStr, err = tok.SignedString(gjwtPriv)
	if err != nil {
		t.Fatalf("iter %d: golang-jwt sign: %v", i, err)
	}
	verifier := jwt.New([]jwk.PublicKey{pub})
	if _, err := verifier.VerifyJWT(tokenStr); err != nil {
		t.Fatalf("iter %d: our verify: %v", i, err)
	}
}

// --- Our sign, their verify (all algorithms) ---

func TestOurSignTheirVerify_EdDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	assertOurSignTheirVerify(t,
		jwk.PrivateKey{KID: "k1", Signer: priv},
		gjwt.SigningMethodEdDSA, pub, "user-eddsa")
}

func TestOurSignTheirVerify_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertOurSignTheirVerify(t,
		jwk.PrivateKey{KID: "k1", Signer: priv},
		gjwt.SigningMethodES256, &priv.PublicKey, "user-es256")
}

func TestOurSignTheirVerify_ES384(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertOurSignTheirVerify(t,
		jwk.PrivateKey{KID: "k1", Signer: priv},
		gjwt.SigningMethodES384, &priv.PublicKey, "user-es384")
}

func TestOurSignTheirVerify_ES512(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertOurSignTheirVerify(t,
		jwk.PrivateKey{KID: "k1", Signer: priv},
		gjwt.SigningMethodES512, &priv.PublicKey, "user-es512")
}

func TestOurSignTheirVerify_RS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	assertOurSignTheirVerify(t,
		jwk.PrivateKey{KID: "k1", Signer: priv},
		gjwt.SigningMethodRS256, &priv.PublicKey, "user-rs256")
}

// --- Their sign, our verify (all algorithms) ---

func TestTheirSignOurVerify_EdDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	assertTheirSignOurVerify(t,
		gjwt.SigningMethodEdDSA, priv, "k1",
		jwk.PublicKey{CryptoPublicKey: pub, KID: "k1"}, "user-eddsa")
}

func TestTheirSignOurVerify_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertTheirSignOurVerify(t,
		gjwt.SigningMethodES256, priv, "k1",
		jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "k1"}, "user-es256")
}

func TestTheirSignOurVerify_ES384(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertTheirSignOurVerify(t,
		gjwt.SigningMethodES384, priv, "k1",
		jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "k1"}, "user-es384")
}

func TestTheirSignOurVerify_ES512(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	assertTheirSignOurVerify(t,
		gjwt.SigningMethodES512, priv, "k1",
		jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "k1"}, "user-es512")
}

func TestTheirSignOurVerify_RS256(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	assertTheirSignOurVerify(t,
		gjwt.SigningMethodRS256, priv, "k1",
		jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "k1"}, "user-rs256")
}

// --- Known key tests ---
//
// Each algorithm uses deterministic key material so failures are reproducible
// across runs. Ed25519 uses NewKeyFromSeed; EC and RSA use a SHA-256 hash
// chain seeded from a fixed string.

func TestKnownKeys(t *testing.T) {
	t.Run("EdDSA", func(t *testing.T) {
		seed := make([]byte, ed25519.SeedSize)
		for i := range seed {
			seed[i] = byte(i)
		}
		priv := ed25519.NewKeyFromSeed(seed)
		pub := priv.Public().(ed25519.PublicKey)
		kid := "known-ed"
		pk := jwk.PrivateKey{KID: kid, Signer: priv}
		pubKey := jwk.PublicKey{CryptoPublicKey: pub, KID: kid}
		assertOurSignTheirVerify(t, pk, gjwt.SigningMethodEdDSA, pub, "known-ed-ours")
		assertTheirSignOurVerify(t, gjwt.SigningMethodEdDSA, priv, kid, pubKey, "known-ed-theirs")
	})

	t.Run("ES256", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), deterministicRand("known-es256"))
		if err != nil {
			t.Fatal(err)
		}
		kid := "known-es256"
		pk := jwk.PrivateKey{KID: kid, Signer: priv}
		pubKey := jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: kid}
		assertOurSignTheirVerify(t, pk, gjwt.SigningMethodES256, &priv.PublicKey, "known-es256-ours")
		assertTheirSignOurVerify(t, gjwt.SigningMethodES256, priv, kid, pubKey, "known-es256-theirs")
	})

	t.Run("ES384", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P384(), deterministicRand("known-es384"))
		if err != nil {
			t.Fatal(err)
		}
		kid := "known-es384"
		pk := jwk.PrivateKey{KID: kid, Signer: priv}
		pubKey := jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: kid}
		assertOurSignTheirVerify(t, pk, gjwt.SigningMethodES384, &priv.PublicKey, "known-es384-ours")
		assertTheirSignOurVerify(t, gjwt.SigningMethodES384, priv, kid, pubKey, "known-es384-theirs")
	})

	t.Run("ES512", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P521(), deterministicRand("known-es512"))
		if err != nil {
			t.Fatal(err)
		}
		kid := "known-es512"
		pk := jwk.PrivateKey{KID: kid, Signer: priv}
		pubKey := jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: kid}
		assertOurSignTheirVerify(t, pk, gjwt.SigningMethodES512, &priv.PublicKey, "known-es512-ours")
		assertTheirSignOurVerify(t, gjwt.SigningMethodES512, priv, kid, pubKey, "known-es512-theirs")
	})

	t.Run("RS256", func(t *testing.T) {
		priv, err := rsa.GenerateKey(deterministicRand("known-rs256"), 2048)
		if err != nil {
			t.Fatal(err)
		}
		kid := "known-rs256"
		pk := jwk.PrivateKey{KID: kid, Signer: priv}
		pubKey := jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: kid}
		assertOurSignTheirVerify(t, pk, gjwt.SigningMethodRS256, &priv.PublicKey, "known-rs256-ours")
		assertTheirSignOurVerify(t, gjwt.SigningMethodRS256, priv, kid, pubKey, "known-rs256-theirs")
	})
}

// --- Stress tests ---
//
// Each subtest generates 1,000 random keys and signs+verifies in both
// directions per key. This catches edge cases in ASN.1 DER-to-raw signature
// conversion (ECDSA r/s values that are shorter than the field size and
// need left-padding) and any key-dependent encoding quirks.
//
// RSA keygen is inherently slow (~10ms per 2048-bit key); use -short to
// reduce RSA iterations to 10.

func TestStress(t *testing.T) {
	t.Run("EdDSA", func(t *testing.T) {
		t.Parallel()
		for i := range 1000 {
			_, priv, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				t.Fatalf("iter %d: keygen: %v", i, err)
			}
			pub := priv.Public().(ed25519.PublicKey)
			kid := fmt.Sprintf("s%d", i)
			stressIteration(t, i,
				jwk.PrivateKey{KID: kid, Signer: priv},
				jwk.PublicKey{CryptoPublicKey: pub, KID: kid},
				gjwt.SigningMethodEdDSA, priv, pub)
		}
	})

	t.Run("ES256", func(t *testing.T) {
		t.Parallel()
		for i := range 1000 {
			priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("iter %d: keygen: %v", i, err)
			}
			kid := fmt.Sprintf("s%d", i)
			stressIteration(t, i,
				jwk.PrivateKey{KID: kid, Signer: priv},
				jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: kid},
				gjwt.SigningMethodES256, priv, &priv.PublicKey)
		}
	})

	t.Run("ES384", func(t *testing.T) {
		t.Parallel()
		for i := range 1000 {
			priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
			if err != nil {
				t.Fatalf("iter %d: keygen: %v", i, err)
			}
			kid := fmt.Sprintf("s%d", i)
			stressIteration(t, i,
				jwk.PrivateKey{KID: kid, Signer: priv},
				jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: kid},
				gjwt.SigningMethodES384, priv, &priv.PublicKey)
		}
	})

	t.Run("ES512", func(t *testing.T) {
		t.Parallel()
		for i := range 1000 {
			priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
			if err != nil {
				t.Fatalf("iter %d: keygen: %v", i, err)
			}
			kid := fmt.Sprintf("s%d", i)
			stressIteration(t, i,
				jwk.PrivateKey{KID: kid, Signer: priv},
				jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: kid},
				gjwt.SigningMethodES512, priv, &priv.PublicKey)
		}
	})

	t.Run("RS256", func(t *testing.T) {
		t.Parallel()
		n := 1000
		if testing.Short() {
			n = 10
		}
		for i := range n {
			priv, err := rsa.GenerateKey(rand.Reader, 2048)
			if err != nil {
				t.Fatalf("iter %d: keygen: %v", i, err)
			}
			kid := fmt.Sprintf("s%d", i)
			stressIteration(t, i,
				jwk.PrivateKey{KID: kid, Signer: priv},
				jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: kid},
				gjwt.SigningMethodRS256, priv, &priv.PublicKey)
		}
	})
}

// --- JWK private key round-trip ---
//
// Marshal a private key to JWK JSON, unmarshal it back, and confirm the
// recovered key produces tokens verifiable by both the original public key
// and golang-jwt.

func TestJWKPrivateKeyRoundTrip(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		original, err := jwk.NewPrivateKey()
		if err != nil {
			t.Fatal(err)
		}
		assertPrivateKeyRoundTrip(t, original,
			gjwt.SigningMethodEdDSA, original.Signer.Public().(ed25519.PublicKey))
	})

	t.Run("EC_P256", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		original := &jwk.PrivateKey{KID: "ec256-rt", Signer: priv}
		assertPrivateKeyRoundTrip(t, original,
			gjwt.SigningMethodES256, &priv.PublicKey)
	})

	t.Run("EC_P384", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		original := &jwk.PrivateKey{KID: "ec384-rt", Signer: priv}
		assertPrivateKeyRoundTrip(t, original,
			gjwt.SigningMethodES384, &priv.PublicKey)
	})

	t.Run("EC_P521", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		original := &jwk.PrivateKey{KID: "ec521-rt", Signer: priv}
		assertPrivateKeyRoundTrip(t, original,
			gjwt.SigningMethodES512, &priv.PublicKey)
	})

	t.Run("RSA", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		original := &jwk.PrivateKey{KID: "rsa-rt", Signer: priv}
		assertPrivateKeyRoundTrip(t, original,
			gjwt.SigningMethodRS256, &priv.PublicKey)
	})
}

func assertPrivateKeyRoundTrip(t *testing.T, original *jwk.PrivateKey, gjwtMethod gjwt.SigningMethod, gjwtPub any) {
	t.Helper()

	// Marshal to JSON.
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Unmarshal back.
	var recovered jwk.PrivateKey
	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if recovered.KID != original.KID {
		t.Errorf("KID: got %q, want %q", recovered.KID, original.KID)
	}

	claims := testClaims("pk-roundtrip")

	// Sign with recovered key, verify with original pubkey.
	signer, err := jwt.NewSigner([]jwk.PrivateKey{recovered})
	if err != nil {
		t.Fatal(err)
	}
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifier := jwt.New([]jwk.PublicKey{*original.PublicKey()})
	if _, err := verifier.VerifyJWT(tokenStr); err != nil {
		t.Errorf("verify with original pubkey: %v", err)
	}

	// Sign with original key, verify with recovered pubkey.
	origSigner, err := jwt.NewSigner([]jwk.PrivateKey{*original})
	if err != nil {
		t.Fatal(err)
	}
	tokenStr2, err := origSigner.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}
	verifier2 := jwt.New([]jwk.PublicKey{*recovered.PublicKey()})
	if _, err := verifier2.VerifyJWT(tokenStr2); err != nil {
		t.Errorf("verify with recovered pubkey: %v", err)
	}

	// Cross-verify with golang-jwt.
	_, err = gjwt.ParseWithClaims(tokenStr, &gjwt.RegisteredClaims{}, func(tok *gjwt.Token) (any, error) {
		return gjwtPub, nil
	})
	if err != nil {
		t.Errorf("golang-jwt cross-verify: %v", err)
	}
}

// --- JWK public key round-trip ---
//
// Marshal a public key to JWK JSON, unmarshal it back, and confirm the
// round-tripped key verifies tokens signed by the original private key.

func TestJWKPublicKeyRoundTrip(t *testing.T) {
	t.Run("Ed25519", func(t *testing.T) {
		_, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		pub := priv.Public().(ed25519.PublicKey)
		signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "ed-pub-rt", Signer: priv}})
		if err != nil {
			t.Fatal(err)
		}
		assertPublicKeyRoundTrip(t,
			jwk.PublicKey{CryptoPublicKey: pub, KID: "ed-pub-rt"},
			signer, pub)
	})

	t.Run("EC_P256", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "ec256-pub-rt", Signer: priv}})
		if err != nil {
			t.Fatal(err)
		}
		assertPublicKeyRoundTrip(t,
			jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "ec256-pub-rt"},
			signer, &priv.PublicKey)
	})

	t.Run("EC_P384", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "ec384-pub-rt", Signer: priv}})
		if err != nil {
			t.Fatal(err)
		}
		assertPublicKeyRoundTrip(t,
			jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "ec384-pub-rt"},
			signer, &priv.PublicKey)
	})

	t.Run("EC_P521", func(t *testing.T) {
		priv, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "ec521-pub-rt", Signer: priv}})
		if err != nil {
			t.Fatal(err)
		}
		assertPublicKeyRoundTrip(t,
			jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "ec521-pub-rt"},
			signer, &priv.PublicKey)
	})

	t.Run("RSA", func(t *testing.T) {
		priv, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatal(err)
		}
		signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "rsa-pub-rt", Signer: priv}})
		if err != nil {
			t.Fatal(err)
		}
		assertPublicKeyRoundTrip(t,
			jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "rsa-pub-rt"},
			signer, &priv.PublicKey)
	})
}

func assertPublicKeyRoundTrip(t *testing.T, origPub jwk.PublicKey, signer *jwt.Signer, gjwtPub any) {
	t.Helper()

	// Marshal to JSON.
	data, err := json.Marshal(origPub)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	// Unmarshal back.
	var recovered jwk.PublicKey
	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if recovered.KID != origPub.KID {
		t.Errorf("KID: got %q, want %q", recovered.KID, origPub.KID)
	}

	// Sign and verify with the round-tripped key.
	tokenStr, err := signer.SignToString(testClaims("pub-roundtrip"))
	if err != nil {
		t.Fatal(err)
	}
	verifier := jwt.New([]jwk.PublicKey{recovered})
	if _, err := verifier.VerifyJWT(tokenStr); err != nil {
		t.Errorf("verify with round-tripped pubkey: %v", err)
	}

	// Cross-verify with golang-jwt.
	_, err = gjwt.ParseWithClaims(tokenStr, &gjwt.RegisteredClaims{}, func(tok *gjwt.Token) (any, error) {
		return gjwtPub, nil
	})
	if err != nil {
		t.Errorf("golang-jwt cross-verify: %v", err)
	}
}

// --- JWKS round-trip ---

// TestJWKSRoundTrip marshals a full JWKS document containing all supported
// key types and verifies that tokens signed with each key are verifiable
// after unmarshal.
func TestJWKSRoundTrip(t *testing.T) {
	edKey, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	ec256, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ec521, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	keys := []jwk.PrivateKey{
		*edKey,
		{KID: "ec256", Signer: ec256},
		{KID: "ec384", Signer: ec384},
		{KID: "ec521", Signer: ec521},
		{KID: "rsa", Signer: rsaKey},
	}
	signer, err := jwt.NewSigner(keys)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize the JWKS (public keys only).
	jwksData, err := json.Marshal(&signer)
	if err != nil {
		t.Fatalf("marshal JWKS: %v", err)
	}

	// Parse it back.
	var jwks jwk.JWKs
	if err := json.Unmarshal(jwksData, &jwks); err != nil {
		t.Fatalf("unmarshal JWKS: %v", err)
	}
	if len(jwks.Keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(jwks.Keys))
	}

	verifier := jwt.New(jwks.Keys)
	claims := testClaims("jwks-round-trip")

	// Sign with each key (round-robin) and verify all.
	for i := range len(keys) {
		tokenStr, err := signer.SignToString(claims)
		if err != nil {
			t.Fatalf("sign[%d]: %v", i, err)
		}
		if _, err := verifier.VerifyJWT(tokenStr); err != nil {
			t.Errorf("verify[%d] after JWKS round-trip: %v", i, err)
		}
	}
}
