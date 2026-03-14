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
//   - Our sign + their verify (Ed25519, EC P-256)
//   - Their sign + our verify (Ed25519, EC P-256)
//   - JWK key round-trip: marshal/unmarshal private and public keys, then
//     confirm the recovered keys interoperate correctly.
package roundtrip_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	gjwt "github.com/golang-jwt/jwt/v5"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// --- Our sign, their verify ---

// TestOurSignTheirVerify_EdDSA signs a token with our Signer (Ed25519) and
// verifies it with golang-jwt's ParseWithClaims.
func TestOurSignTheirVerify_EdDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)

	signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "k1", Signer: priv}})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "user123",
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
	}
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := gjwt.ParseWithClaims(tokenStr, &gjwt.RegisteredClaims{}, func(t *gjwt.Token) (any, error) {
		if _, ok := t.Method.(*gjwt.SigningMethodEd25519); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return pub, nil
	})
	if err != nil {
		t.Fatalf("golang-jwt verify failed: %v", err)
	}
	rc, ok := parsed.Claims.(*gjwt.RegisteredClaims)
	if !ok || !parsed.Valid {
		t.Fatal("token invalid or claims unreadable")
	}
	if rc.Subject != claims.Sub {
		t.Errorf("sub: got %q, want %q", rc.Subject, claims.Sub)
	}
	if rc.Issuer != claims.Iss {
		t.Errorf("iss: got %q, want %q", rc.Issuer, claims.Iss)
	}
}

// TestOurSignTheirVerify_ES256 signs with our Signer (EC P-256 / ES256) and
// verifies with golang-jwt.
func TestOurSignTheirVerify_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "k1", Signer: priv}})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "user456",
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
	}
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := gjwt.ParseWithClaims(tokenStr, &gjwt.RegisteredClaims{}, func(t *gjwt.Token) (any, error) {
		if _, ok := t.Method.(*gjwt.SigningMethodECDSA); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return &priv.PublicKey, nil
	})
	if err != nil {
		t.Fatalf("golang-jwt verify failed: %v", err)
	}
	rc, ok := parsed.Claims.(*gjwt.RegisteredClaims)
	if !ok || !parsed.Valid {
		t.Fatal("token invalid or claims unreadable")
	}
	if rc.Subject != claims.Sub {
		t.Errorf("sub: got %q, want %q", rc.Subject, claims.Sub)
	}
}

// --- Their sign, our verify ---

// TestTheirSignOurVerify_EdDSA signs a token with golang-jwt (Ed25519) and
// verifies it with our Verifier.
func TestTheirSignOurVerify_EdDSA(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	const kid = "k1"

	now := time.Now()
	gClaims := gjwt.RegisteredClaims{
		Issuer:    "https://example.com",
		Subject:   "user123",
		ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  gjwt.NewNumericDate(now),
	}
	tok := gjwt.NewWithClaims(gjwt.SigningMethodEdDSA, gClaims)
	tok.Header["kid"] = kid
	tokenStr, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	verifier := jwt.New([]jwk.PublicKey{{CryptoPublicKey: pub, KID: kid}})
	jws, err := verifier.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("our verify failed: %v", err)
	}

	var decoded jwt.IDTokenClaims
	if err := jwt.UnmarshalClaims(jws, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if decoded.Sub != gClaims.Subject {
		t.Errorf("sub: got %q, want %q", decoded.Sub, gClaims.Subject)
	}
	if decoded.Iss != gClaims.Issuer {
		t.Errorf("iss: got %q, want %q", decoded.Iss, gClaims.Issuer)
	}
}

// TestTheirSignOurVerify_ES256 signs with golang-jwt (EC P-256) and verifies
// with our Verifier.
func TestTheirSignOurVerify_ES256(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	const kid = "k1"

	now := time.Now()
	gClaims := gjwt.RegisteredClaims{
		Issuer:    "https://example.com",
		Subject:   "user456",
		ExpiresAt: gjwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt:  gjwt.NewNumericDate(now),
	}
	tok := gjwt.NewWithClaims(gjwt.SigningMethodES256, gClaims)
	tok.Header["kid"] = kid
	tokenStr, err := tok.SignedString(priv)
	if err != nil {
		t.Fatal(err)
	}

	verifier := jwt.New([]jwk.PublicKey{{CryptoPublicKey: &priv.PublicKey, KID: kid}})
	jws, err := verifier.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("our verify failed: %v", err)
	}

	var decoded jwt.IDTokenClaims
	if err := jwt.UnmarshalClaims(jws, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if decoded.Sub != gClaims.Subject {
		t.Errorf("sub: got %q, want %q", decoded.Sub, gClaims.Subject)
	}
}

// --- JWK key round-trip ---

// TestJWKPrivateKeyRoundTrip marshals a private key (Ed25519) to JWK JSON and
// unmarshals it back. Confirms the recovered key signs tokens that the original
// public key verifies, and vice versa.
func TestJWKPrivateKeyRoundTrip(t *testing.T) {
	original, err := jwk.NewPrivateKey() // Ed25519
	if err != nil {
		t.Fatal(err)
	}

	// Marshal the private key to JWK JSON.
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("marshal private key: %v", err)
	}

	// Unmarshal it back.
	var recovered jwk.PrivateKey
	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatalf("unmarshal private key: %v", err)
	}
	if recovered.KID != original.KID {
		t.Errorf("KID mismatch: got %q, want %q", recovered.KID, original.KID)
	}

	// Sign with the recovered key.
	signer, err := jwt.NewSigner([]jwk.PrivateKey{recovered})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "round-trip",
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
	}
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with the original public key.
	verifier := jwt.New([]jwk.PublicKey{*original.PublicKey()})
	if _, err := verifier.VerifyJWT(tokenStr); err != nil {
		t.Errorf("verify with original pubkey after key round-trip: %v", err)
	}

	// Also sign with the original and verify with the recovered public key.
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
		t.Errorf("verify with recovered pubkey after key round-trip: %v", err)
	}
}

// TestJWKPublicKeyRoundTrip marshals an EC P-256 public key to JWK JSON,
// unmarshals it back, and confirms the round-tripped key verifies tokens
// signed with the original private key.
func TestJWKPublicKeyRoundTrip(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	origPub := jwk.PublicKey{CryptoPublicKey: &priv.PublicKey, KID: "ec-test"}

	// Marshal the public key.
	data, err := json.Marshal(origPub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}

	// Unmarshal it back.
	var recovered jwk.PublicKey
	if err := json.Unmarshal(data, &recovered); err != nil {
		t.Fatalf("unmarshal public key: %v", err)
	}
	if recovered.KID != origPub.KID {
		t.Errorf("KID mismatch: got %q, want %q", recovered.KID, origPub.KID)
	}

	// Sign with the original private key.
	signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: origPub.KID, Signer: priv}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "pubkey-round-trip",
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
	}
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Verify with the round-tripped public key.
	verifier := jwt.New([]jwk.PublicKey{recovered})
	if _, err := verifier.VerifyJWT(tokenStr); err != nil {
		t.Errorf("verify with round-tripped public key: %v", err)
	}

	// Cross-check: golang-jwt also verifies our token using the original key.
	_, err = gjwt.ParseWithClaims(tokenStr, &gjwt.RegisteredClaims{}, func(t *gjwt.Token) (any, error) {
		return &priv.PublicKey, nil
	})
	if err != nil {
		t.Errorf("golang-jwt cross-verify failed: %v", err)
	}
}

// TestJWKSRoundTrip marshals a full JWKS document (multiple keys) and verifies
// that tokens signed with each key are verifiable after unmarshal.
func TestJWKSRoundTrip(t *testing.T) {
	edKey, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecKey := jwk.PrivateKey{KID: "ec-1", Signer: ecPriv}

	signer, err := jwt.NewSigner([]jwk.PrivateKey{*edKey, ecKey})
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
	if len(jwks.Keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(jwks.Keys))
	}

	verifier := jwt.New(jwks.Keys)
	now := time.Now()
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "jwks-round-trip",
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
	}

	// Sign two tokens (round-robin across both keys) and verify both.
	for i := range 2 {
		tokenStr, err := signer.SignToString(claims)
		if err != nil {
			t.Fatalf("sign[%d]: %v", i, err)
		}
		if _, err := verifier.VerifyJWT(tokenStr); err != nil {
			t.Errorf("verify[%d] after JWKS round-trip: %v", i, err)
		}
	}
}
