// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"crypto"
	"errors"
	"testing"
	"time"
)

func makeHMACSigner(tb testing.TB, hash crypto.Hash, secret []byte) *HMACSigner {
	tb.Helper()
	key, err := NewSharedSecret(secret, "")
	if err != nil {
		tb.Fatalf("NewSharedSecret: %v", err)
	}
	signer, err := NewHMACSigner(hash, key)
	if err != nil {
		tb.Fatalf("NewHMACSigner: %v", err)
	}
	return signer
}

func makeHMACVerifier(tb testing.TB, hash crypto.Hash, secret []byte) *HMACVerifier {
	tb.Helper()
	key, err := NewSharedSecret(secret, "")
	if err != nil {
		tb.Fatalf("NewSharedSecret: %v", err)
	}
	verifier, err := NewHMACVerifier(hash, key)
	if err != nil {
		tb.Fatalf("NewHMACVerifier: %v", err)
	}
	return verifier
}

func TestHMACSigner_SignToString(t *testing.T) {
	secret := []byte("test-secret-that-is-long-enough-for-hs256")
	signer := makeHMACSigner(t, crypto.SHA256, secret)

	claims := &TokenClaims{
		Iss: "test-issuer",
		Sub: "user-42",
		Aud: Listish{"api"},
		Exp: time.Now().Add(time.Hour).Unix(),
		IAt: time.Now().Unix(),
	}

	token, err := signer.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	// Verify structure: three base64url segments
	parts := 0
	for _, c := range token {
		if c == '.' {
			parts++
		}
	}
	if parts != 2 {
		t.Errorf("expected 2 dots in token, got %d", parts)
	}

	// Verify we can decode and verify
	verifier := signer.Verifier()
	jws, err := verifier.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}

	var decoded TokenClaims
	if err := jws.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}

	if decoded.Iss != "test-issuer" {
		t.Errorf("iss = %q, want %q", decoded.Iss, "test-issuer")
	}
	if decoded.Sub != "user-42" {
		t.Errorf("sub = %q, want %q", decoded.Sub, "user-42")
	}
}

func TestHMACSigner_Sign(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	signer := makeHMACSigner(t, crypto.SHA256, secret)

	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	jws, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if jws.GetHeader().Alg != "HS256" {
		t.Errorf("alg = %q, want %q", jws.GetHeader().Alg, "HS256")
	}

	// KID is empty because the key has no KID set
	if jws.GetHeader().KID != "" {
		t.Errorf("KID = %q, want empty", jws.GetHeader().KID)
	}

	if len(jws.GetSignature()) == 0 {
		t.Error("signature is empty")
	}

	token, err := jws.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	verifier := signer.Verifier()
	_, err = verifier.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
}

func TestHMACSigner_SignJWT(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	signer := makeHMACSigner(t, crypto.SHA256, secret)

	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	jws, err := New(claims)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Header should be empty initially
	if jws.GetHeader().Alg != "" {
		t.Errorf("initial alg = %q, want empty", jws.GetHeader().Alg)
	}

	if err := signer.SignJWT(jws); err != nil {
		t.Fatalf("SignJWT: %v", err)
	}

	if jws.GetHeader().Alg != "HS256" {
		t.Errorf("alg = %q, want %q", jws.GetHeader().Alg, "HS256")
	}

	// KID is empty because the key has no KID set
	if jws.GetHeader().KID != "" {
		t.Errorf("KID = %q, want empty", jws.GetHeader().KID)
	}

	if len(jws.GetSignature()) == 0 {
		t.Error("signature is empty after signing")
	}
}

func TestHMACSigner_KID(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	key := newSharedSecret(t, secret, "my-hmac-key")
	signer, err := NewHMACSigner(crypto.SHA256, key)
	if err != nil {
		t.Fatalf("NewHMACSigner: %v", err)
	}

	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	jws, err := signer.Sign(claims)
	if err != nil {
		t.Fatalf("Sign: %v", err)
	}

	if jws.GetHeader().KID != "my-hmac-key" {
		t.Errorf("KID = %q, want %q", jws.GetHeader().KID, "my-hmac-key")
	}
	if jws.GetHeader().Alg != "HS256" {
		t.Errorf("alg = %q, want %q", jws.GetHeader().Alg, "HS256")
	}

	// Verify round-trip works
	token, encErr := jws.Encode()
	if encErr != nil {
		t.Fatalf("Encode: %v", encErr)
	}
	verifier := signer.Verifier()
	_, err = verifier.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
}

func TestHMACSigner_AlgConflict(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	signer := makeHMACSigner(t, crypto.SHA256, secret)

	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	jws, err := New(claims)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	// Set a conflicting algorithm
	hdr := jws.GetHeader()
	hdr.Alg = "HS384"
	if err := jws.SetHeader(&hdr); err != nil {
		t.Fatalf("SetHeader: %v", err)
	}

	err = signer.SignJWT(jws)
	if err == nil {
		t.Fatal("expected error for alg conflict, got nil")
	}
	if err != ErrAlgConflict {
		t.Errorf("error = %v, want %v", err, ErrAlgConflict)
	}
}

func TestNewHMACSigner_NilSecret(t *testing.T) {
	_, err := NewHMACSigner(crypto.SHA256, nil)
	if err == nil {
		t.Fatal("expected error for nil secret, got nil")
	}
	if !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("error = %v, want %v", err, ErrNoSigningKey)
	}
}

func TestNewHMACSigner_InvalidAlgorithm(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	key, err := NewSharedSecret(secret, "")
	if err != nil {
		t.Fatalf("NewSharedSecret: %v", err)
	}
	_, err = NewHMACSigner(crypto.Hash(99), key)
	if err == nil {
		t.Fatal("expected error for invalid algorithm, got nil")
	}
}

func TestHMACSigner_Verifier(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	signer := makeHMACSigner(t, crypto.SHA256, secret)
	verifier := signer.Verifier()

	if verifier.alg != crypto.SHA256 {
		t.Errorf("verifier alg = %v, want %v", verifier.alg, crypto.SHA256)
	}
}

func TestHMACSigner_SignRaw(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	signer := makeHMACSigner(t, crypto.SHA256, secret)

	// Test with a simple header
	hdr := &RFCHeader{Alg: "", KID: "my-key", Typ: "JWT"}
	payload := []byte(`{"sub":"user"}`)

	raw, err := signer.SignRaw(hdr, payload)
	if err != nil {
		t.Fatalf("SignRaw: %v", err)
	}

	if len(raw.Protected) == 0 {
		t.Error("protected is empty")
	}
	if len(raw.Payload) == 0 {
		t.Error("payload is empty")
	}
	if len(raw.Signature) == 0 {
		t.Error("signature is empty")
	}

	// Verify the signature by round-tripping through Encode/VerifyJWT
	jws, err := New(&TokenClaims{Sub: "test"})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	if err := signer.SignJWT(jws); err != nil {
		t.Fatalf("SignJWT: %v", err)
	}

	token, err := jws.Encode()
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	verifier := signer.Verifier()
	_, err = verifier.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}
}

func TestAllAlgorithms(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-all-algorithms")

	for _, hash := range []crypto.Hash{crypto.SHA256, crypto.SHA384, crypto.SHA512} {
		t.Run(hash.String(), func(t *testing.T) {
			signer := makeHMACSigner(t, hash, secret)
			verifier := signer.Verifier()

			claims := &TokenClaims{
				Iss: "test",
				Sub: "user",
				Exp: time.Now().Add(time.Hour).Unix(),
			}

			token, err := signer.SignToString(claims)
			if err != nil {
				t.Fatalf("SignToString: %v", err)
			}

			jws, err := verifier.VerifyJWT(token)
			if err != nil {
				t.Fatalf("VerifyJWT: %v", err)
			}

			expectedAlg := signer.algorithm()
			if jws.GetHeader().Alg != expectedAlg {
				t.Errorf("alg = %q, want %q", jws.GetHeader().Alg, expectedAlg)
			}
		})
	}
}

func TestHMACVerifier_AlgorithmMismatch(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")

	signer := makeHMACSigner(t, crypto.SHA256, secret)
	verifier := makeHMACVerifier(t, crypto.SHA384, secret)

	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	token, err := signer.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	_, err = verifier.VerifyJWT(token)
	if err == nil {
		t.Fatal("expected error for algorithm mismatch, got nil")
	}
}

func TestHMACVerifier_WrongSecret(t *testing.T) {
	secret := []byte("correct-secret-long-enough-for-hs256")
	wrongSecret := []byte("wrong-secret-long-enough-for-hs256")

	signer := makeHMACSigner(t, crypto.SHA256, secret)
	verifier := makeHMACVerifier(t, crypto.SHA256, wrongSecret)

	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	token, err := signer.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	_, err = verifier.VerifyJWT(token)
	if err == nil {
		t.Fatal("expected error for wrong secret, got nil")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("error = %v, want %v", err, ErrSignatureInvalid)
	}
}

func TestNewHMACVerifier_NilSecret(t *testing.T) {
	_, err := NewHMACVerifier(crypto.SHA256, nil)
	if err == nil {
		t.Fatal("expected error for nil secret, got nil")
	}
	if !errors.Is(err, ErrNoVerificationKey) {
		t.Errorf("error = %v, want %v", err, ErrNoVerificationKey)
	}
}

func TestHMACVerifier_RetiredKeys(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	retiredSecret := []byte("retired-secret-long-enough-for-hs256")

	active, err := NewSharedSecret(secret, "active")
	if err != nil {
		t.Fatalf("NewSharedSecret active: %v", err)
	}
	retired, err := NewSharedSecret(retiredSecret, "retired")
	if err != nil {
		t.Fatalf("NewSharedSecret retired: %v", err)
	}

	verifier, err := NewHMACVerifier(crypto.SHA256, active, retired)
	if err != nil {
		t.Fatalf("NewHMACVerifier: %v", err)
	}

	// Sign with active key
	signer := makeHMACSigner(t, crypto.SHA256, secret)
	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	token, err := signer.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	// Verify with verifier that has retired key
	_, err = verifier.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT with retired: %v", err)
	}

	// Sign with retired key
	retiredSigner := makeHMACSigner(t, crypto.SHA256, retiredSecret)
	retiredToken, err := retiredSigner.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString retired: %v", err)
	}

	// Verify retired token with active+retired verifier
	_, err = verifier.VerifyJWT(retiredToken)
	if err != nil {
		t.Fatalf("VerifyJWT retired token: %v", err)
	}

	// Verify retired token with active-only verifier should fail
	activeOnly, err := NewHMACVerifier(crypto.SHA256, active)
	if err != nil {
		t.Fatalf("NewHMACVerifier active-only: %v", err)
	}
	_, err = activeOnly.VerifyJWT(retiredToken)
	if err == nil {
		t.Fatal("expected error for retired token with active-only verifier")
	}
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Errorf("error = %v, want %v", err, ErrSignatureInvalid)
	}
}

func TestSharedSecret_Thumbprint(t *testing.T) {
	secret := []byte("test-secret-long-enough")
	ss, err := NewSharedSecret(secret, "my-key")
	if err != nil {
		t.Fatalf("NewSharedSecret: %v", err)
	}

	thumb, err := ss.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	if thumb == "" {
		t.Error("thumbprint is empty")
	}

	// Thumbprint should not include KID
	ss2, err := NewSharedSecret([]byte("test-secret-long-enough"), "different-key")
	if err != nil {
		t.Fatalf("NewSharedSecret: %v", err)
	}
	thumb2, err := ss2.Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint: %v", err)
	}

	if thumb != thumb2 {
		t.Error("thumbprints differ for same secret with different KID")
	}
}

func TestSharedSecret_MarshalUnmarshal(t *testing.T) {
	secret := []byte("test-secret-long-enough")
	ss, err := NewSharedSecret(secret, "my-key")
	if err != nil {
		t.Fatalf("NewSharedSecret: %v", err)
	}

	data, err := ss.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var ss2 SharedSecret
	if err := ss2.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if string(ss2.secret) != string(secret) {
		t.Errorf("secret = %q, want %q", ss2.secret, secret)
	}

	if ss2.KID != "my-key" {
		t.Errorf("KID = %q, want %q", ss2.KID, "my-key")
	}
}

func TestSharedSecret_MarshalUnmarshal_NoKID(t *testing.T) {
	secret := []byte("test-secret-long-enough")
	ss := &SharedSecret{secret: secret} // no KID

	data, err := ss.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	var ss2 SharedSecret
	if err := ss2.UnmarshalJSON(data); err != nil {
		t.Fatalf("UnmarshalJSON: %v", err)
	}

	if ss2.KID != "" {
		t.Errorf("KID = %q, want empty", ss2.KID)
	}
}

func TestSharedSecret_UnmarshalJSON_EmptyK(t *testing.T) {
	data := []byte(`{"kty":"oct","k":""}`)
	var ss SharedSecret
	err := ss.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error for empty k, got nil")
	}
	if !errors.Is(err, ErrMissingKeyData) {
		t.Errorf("error = %v, want %v", err, ErrMissingKeyData)
	}
}

func TestParseSharedSecretJWK(t *testing.T) {
	secret := []byte("test-secret-long-enough")
	ss, err := NewSharedSecret(secret, "my-key")
	if err != nil {
		t.Fatalf("NewSharedSecret: %v", err)
	}

	data, err := ss.MarshalJSON()
	if err != nil {
		t.Fatalf("MarshalJSON: %v", err)
	}

	parsed, err := ParseSharedSecretJWK(data)
	if err != nil {
		t.Fatalf("ParseSharedSecretJWK: %v", err)
	}

	if string(parsed.secret) != string(secret) {
		t.Errorf("secret = %q, want %q", parsed.secret, secret)
	}

	if parsed.KID != "my-key" {
		t.Errorf("KID = %q, want %q", parsed.KID, "my-key")
	}
}

func TestSharedSecret_KeyType(t *testing.T) {
	ss, err := NewSharedSecret([]byte("test-secret-long-enough"), "")
	if err != nil {
		t.Fatalf("NewSharedSecret: %v", err)
	}
	if ss.KeyType() != "oct" {
		t.Errorf("KeyType() = %q, want %q", ss.KeyType(), "oct")
	}
}

// newSharedSecret is a test helper that panics on error.
func newSharedSecret(tb testing.TB, secret []byte, kid string) *SharedSecret {
	tb.Helper()
	ss, err := NewSharedSecret(secret, kid)
	if err != nil {
		tb.Fatalf("NewSharedSecret: %v", err)
	}
	return ss
}

func TestNewSharedSecret_ShortSecret(t *testing.T) {
	_, err := NewSharedSecret([]byte("short"), "")
	if err == nil {
		t.Fatal("expected error for short secret, got nil")
	}
	if !errors.Is(err, ErrKeyTooSmall) {
		t.Errorf("error = %v, want %v", err, ErrKeyTooSmall)
	}
}

func TestNewSharedSecret_EmptySecret(t *testing.T) {
	_, err := NewSharedSecret([]byte{}, "")
	if err == nil {
		t.Fatal("expected error for empty secret, got nil")
	}
	if !errors.Is(err, ErrNoSigningKey) {
		t.Errorf("error = %v, want %v", err, ErrNoSigningKey)
	}
}

func TestNewHMACVerifier_NilRetired(t *testing.T) {
	secret := []byte("test-secret-long-enough-for-hs256")
	_, err := NewHMACVerifier(crypto.SHA256, newSharedSecret(t, secret, ""), nil)
	if err == nil {
		t.Fatal("expected error for nil retired secret, got nil")
	}
	if !errors.Is(err, ErrNoVerificationKey) {
		t.Errorf("error = %v, want %v", err, ErrNoVerificationKey)
	}
}

func TestHMACVerifier_KIDMatching(t *testing.T) {
	secret1 := []byte("test-secret-long-enough-for-hs256-one")
	secret2 := []byte("test-secret-long-enough-for-hs256-two")

	key1, err := NewSharedSecret(secret1, "key-one")
	if err != nil {
		t.Fatalf("NewSharedSecret key1: %v", err)
	}
	key2, err := NewSharedSecret(secret2, "key-two")
	if err != nil {
		t.Fatalf("NewSharedSecret key2: %v", err)
	}

	verifier, err := NewHMACVerifier(crypto.SHA256, key2, key1)
	if err != nil {
		t.Fatalf("NewHMACVerifier: %v", err)
	}

	// Sign with key1
	signer1 := makeHMACSigner(t, crypto.SHA256, secret1)
	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	token, err := signer1.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	// Verify with verifier that has key1 as retired — should succeed
	_, err = verifier.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT with matching retired key: %v", err)
	}

	// Sign with key2
	signer2 := makeHMACSigner(t, crypto.SHA256, secret2)
	token2, err := signer2.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString key2: %v", err)
	}

	// Verify with verifier that has key2 as active — should succeed
	_, err = verifier.VerifyJWT(token2)
	if err != nil {
		t.Fatalf("VerifyJWT with matching active key: %v", err)
	}

	// Verify with wrong KID should fail with ErrUnknownKID
	// Sign with a key that has KID set
	signerWithKID, err := NewHMACSigner(crypto.SHA256, key1)
	if err != nil {
		t.Fatalf("NewHMACSigner with KID: %v", err)
	}
	tokenWithKID, err := signerWithKID.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString with KID: %v", err)
	}

	verifierNoKey1, err := NewHMACVerifier(crypto.SHA256, key2)
	if err != nil {
		t.Fatalf("NewHMACVerifier no-key1: %v", err)
	}
	_, err = verifierNoKey1.VerifyJWT(tokenWithKID)
	if err == nil {
		t.Fatal("expected error for KID not found, got nil")
	}
	if !errors.Is(err, ErrUnknownKID) {
		t.Errorf("error = %v, want %v", err, ErrUnknownKID)
	}
}

func TestHMACVerifier_NoKID_TriesAll(t *testing.T) {
	secret1 := []byte("test-secret-long-enough-for-hs256-one")
	secret2 := []byte("test-secret-long-enough-for-hs256-two")

	key1, err := NewSharedSecret(secret1, "")
	if err != nil {
		t.Fatalf("NewSharedSecret key1: %v", err)
	}
	key2, err := NewSharedSecret(secret2, "")
	if err != nil {
		t.Fatalf("NewSharedSecret key2: %v", err)
	}

	verifier, err := NewHMACVerifier(crypto.SHA256, key2, key1)
	if err != nil {
		t.Fatalf("NewHMACVerifier: %v", err)
	}

	// Sign with key1 (no KID)
	signer1 := makeHMACSigner(t, crypto.SHA256, secret1)
	claims := &TokenClaims{
		Iss: "test",
		Sub: "user",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	token, err := signer1.SignToString(claims)
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	// Token has no KID — verifier should try all secrets
	_, err = verifier.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT no-KID token: %v", err)
	}
}

func BenchmarkHMACSigner_SignToString(b *testing.B) {
	secret := []byte("test-secret-long-enough-for-hs256")
	signer := makeHMACSigner(b, crypto.SHA256, secret)

	claims := &TokenClaims{
		Iss: "test-issuer",
		Sub: "user-42",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := signer.SignToString(claims)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkHMACVerifier_VerifyJWT(b *testing.B) {
	secret := []byte("test-secret-long-enough-for-hs256")
	signer := makeHMACSigner(b, crypto.SHA256, secret)
	verifier := signer.Verifier()

	claims := &TokenClaims{
		Iss: "test-issuer",
		Sub: "user-42",
		Exp: time.Now().Add(time.Hour).Unix(),
	}

	token, err := signer.SignToString(claims)
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	b.ReportAllocs()

	for b.Loop() {
		_, err := verifier.VerifyJWT(token)
		if err != nil {
			b.Fatal(err)
		}
	}
}
