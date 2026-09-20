// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"crypto"

	"github.com/therootcompany/golib/auth/jwt"
)

func mustPK(t testing.TB, signer crypto.Signer, kid string) *jwt.PrivateKey {
	t.Helper()
	pk, err := jwt.FromPrivateKey(signer, kid)
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// AppClaims embeds TokenClaims and adds application-specific fields.
//
// Because TokenClaims is embedded, AppClaims satisfies Claims
// for free via Go's method promotion - no interface to implement.
type AppClaims struct {
	jwt.TokenClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// validateAppClaims is a plain function - not a method satisfying an interface.
// It demonstrates the Decode+Verify pattern: custom validation logic lives here,
// calling Validator.Validate and adding app-specific checks.
func validateAppClaims(c AppClaims, v *jwt.Validator, now time.Time) error {
	var errs []error
	if err := v.Validate(nil, &c, now); err != nil {
		errs = append(errs, err)
	}
	if c.Email == "" {
		errs = append(errs, errors.New("missing email claim"))
	}
	return errors.Join(errs...)
}

func goodClaims() AppClaims {
	now := time.Now()
	return AppClaims{
		TokenClaims: jwt.TokenClaims{
			Iss:      "https://example.com",
			Sub:      "user123",
			Aud:      jwt.Listish{"myapp"},
			Exp:      now.Add(time.Hour).Unix(),
			IAt:      now.Unix(),
			AuthTime: now.Unix(),
			AMR:      []string{"pwd"},
			JTI:      "abc123",
			AzP:      "myapp",
			Nonce:    "nonce1",
		},
		Email: "user@example.com",
		Roles: []string{"admin"},
	}
}

// goodValidator configures the ID token validator with iss set to "https://example.com".
// Iss checking is now the Validator's responsibility, not the Verifier's.
func goodValidator() *jwt.Validator {
	return jwt.NewIDTokenValidator(
		[]string{"https://example.com"},
		[]string{"myapp"},
		[]string{"myapp"},
		0,
	)
}

func goodVerifier(pub jwt.PublicKey) *jwt.Verifier {
	v, err := jwt.NewVerifier([]jwt.PublicKey{pub})
	if err != nil {
		panic(err)
	}
	return v
}

// TestRoundTrip is the primary happy path using ES256.
// It demonstrates the full Verify / UnmarshalClaims / Validate flow.
func TestRoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "key-1")})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := signer.Sign(&claims)
	if err != nil {
		t.Fatal(err)
	}
	if jws.GetHeader().Alg != "ES256" {
		t.Fatalf("expected ES256, got %s", jws.GetHeader().Alg)
	}

	token, err := jwt.Encode(jws)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	iss := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if jws2.GetHeader().Alg != "ES256" {
		t.Errorf("expected ES256 alg in jws, got %s", jws2.GetHeader().Alg)
	}

	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if err := goodValidator().Validate(nil, &decoded, time.Now()); err != nil {
		t.Fatalf("claim validation failed: %v", err)
	}
	// Direct field access - no type assertion needed.
	if decoded.Email != claims.Email {
		t.Errorf("email: got %s, want %s", decoded.Email, claims.Email)
	}
}

// TestRoundTripRS256 exercises RSA PKCS#1 v1.5 / RS256.
func TestRoundTripRS256(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "key-1")})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := signer.Sign(&claims)
	if err != nil {
		t.Fatal(err)
	}
	if jws.GetHeader().Alg != "RS256" {
		t.Fatalf("expected RS256, got %s", jws.GetHeader().Alg)
	}

	token, err := jwt.Encode(jws)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	iss := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if err := goodValidator().Validate(nil, &decoded, time.Now()); err != nil {
		t.Fatalf("claim validation failed: %v", err)
	}
}

// TestRoundTripEdDSA exercises Ed25519 / EdDSA (RFC 8037).
func TestRoundTripEdDSA(t *testing.T) {
	pubKeyBytes, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "key-1")})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := signer.Sign(&claims)
	if err != nil {
		t.Fatal(err)
	}
	if jws.GetHeader().Alg != "EdDSA" {
		t.Fatalf("expected EdDSA, got %s", jws.GetHeader().Alg)
	}

	token, err := jwt.Encode(jws)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	iss := goodVerifier(jwt.PublicKey{Pub: pubKeyBytes, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if err := goodValidator().Validate(nil, &decoded, time.Now()); err != nil {
		t.Fatalf("claim validation failed: %v", err)
	}
}

// TestRoundTripES384 exercises ECDSA P-384 / ES384.
func TestRoundTripES384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "key-1")})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := signer.Sign(&claims)
	if err != nil {
		t.Fatal(err)
	}
	if jws.GetHeader().Alg != "ES384" {
		t.Fatalf("expected ES384, got %s", jws.GetHeader().Alg)
	}

	token, err := jwt.Encode(jws)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	iss := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if err := goodValidator().Validate(nil, &decoded, time.Now()); err != nil {
		t.Fatalf("claim validation failed: %v", err)
	}
}

// TestRoundTripES512 exercises ECDSA P-521 / ES512.
func TestRoundTripES512(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "key-1")})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := signer.Sign(&claims)
	if err != nil {
		t.Fatal(err)
	}
	if jws.GetHeader().Alg != "ES512" {
		t.Fatalf("expected ES512, got %s", jws.GetHeader().Alg)
	}

	token, err := jwt.Encode(jws)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}

	iss := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if err := goodValidator().Validate(nil, &decoded, time.Now()); err != nil {
		t.Fatalf("claim validation failed: %v", err)
	}
}

// TestDecodeVerifyFlow demonstrates the Decode + Verify + custom validation pattern.
// The caller owns the full validation pipeline.
func TestDecodeVerifyFlow(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k")})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	iss, _ := jwt.NewVerifier([]jwt.PublicKey{{Pub: &privKey.PublicKey, KID: "k"}})

	jws2, err := jwt.Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if err := iss.Verify(jws2); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}

	if err := goodValidator().Validate(nil, &decoded, time.Now()); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
}

// TestDecodeReturnsParsedOnSigFailure verifies that Decode returns a non-nil
// *StandardJWS even when the token will later fail signature verification.
// Callers can inspect the header (kid, alg) for routing before calling Verify.
func TestDecodeReturnsParsedOnSigFailure(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, signingKey, "k")})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	// Verifier has wrong public key - sig verification will fail.
	iss, _ := jwt.NewVerifier([]jwt.PublicKey{{Pub: &wrongKey.PublicKey, KID: "k"}})

	// Decode always succeeds for well-formed tokens.
	result, err := jwt.Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if result == nil {
		t.Fatal("Decode should return non-nil StandardJWS")
	}
	if result.GetHeader().KID != "k" {
		t.Errorf("expected kid %q, got %q", "k", result.GetHeader().KID)
	}

	// Verify should fail with the wrong key.
	if err := iss.Verify(result); err == nil {
		t.Fatal("expected Verify to fail with wrong key")
	}
}

// TestCustomValidation demonstrates that Validator.Validate is called
// explicitly and custom fields are validated alongside the standard ones.
func TestCustomValidation(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Token with empty Email - our custom validator should reject it.
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k")})
	claims := goodClaims()
	claims.Email = ""
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "k"})
	jws2, err := jwt.Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if err := iss.Verify(jws2); err != nil {
		t.Fatalf("Verify failed unexpectedly: %v", err)
	}

	var decoded AppClaims
	_ = jws2.UnmarshalClaims(&decoded)

	err = validateAppClaims(decoded, goodValidator(), time.Now())
	if err == nil {
		t.Fatal("expected validation to fail: email is empty")
	}
	if !strings.Contains(err.Error(), "missing email claim") {
		t.Fatalf("expected 'missing email claim' in error: %v", err)
	}
}

// TestNBFValidation confirms that a token with nbf in the future is rejected,
// and that a token with nbf in the past (or absent) is accepted.
func TestNBFValidation(t *testing.T) {
	now := time.Now()

	base := AppClaims{
		TokenClaims: jwt.TokenClaims{
			Iss: "https://example.com",
			Aud: jwt.Listish{"myapp"},
			Exp: now.Add(time.Hour).Unix(),
			IAt: now.Unix(),
		},
	}

	v := &jwt.Validator{
		Checks: jwt.CheckIss | jwt.CheckAud | jwt.CheckExp | jwt.CheckIAt | jwt.CheckNBf,
		Iss:    []string{"https://example.com"},
		Aud:    []string{"myapp"},
	}

	// No nbf: should pass.
	if err := v.Validate(nil, &base, now); err != nil {
		t.Fatalf("expected no error without nbf: %v", err)
	}

	// nbf in the past: should pass.
	pastNBF := base
	pastNBF.NBf = now.Add(-time.Hour).Unix()
	if err := v.Validate(nil, &pastNBF, now); err != nil {
		t.Fatalf("expected no error with past nbf: %v", err)
	}

	// nbf in the future: must be rejected.
	futureNBF := base
	futureNBF.NBf = now.Add(time.Hour).Unix()
	err := v.Validate(nil, &futureNBF, now)
	if err == nil {
		t.Fatal("expected error for future nbf")
	}
	if !errors.Is(err, jwt.ErrBeforeNBf) {
		t.Fatalf("expected ErrBeforeNBf, got: %v", err)
	}
}

// TestVerifyWithoutValidation confirms that Verify + UnmarshalClaims succeeds
// independently of claim validation - the caller decides whether to validate.
func TestVerifyWithoutValidation(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k")})
	c := goodClaims()
	token, _ := signer.SignToString(&c)

	iss, _ := jwt.NewVerifier([]jwt.PublicKey{{Pub: &privKey.PublicKey, KID: "k"}})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var claims AppClaims
	if err := jws2.UnmarshalClaims(&claims); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if claims.Email != c.Email {
		t.Errorf("claims not unmarshalled: email got %q, want %q", claims.Email, c.Email)
	}
}

// TestVerifierWrongKey confirms that a different key's public key is rejected.
func TestVerifierWrongKey(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, signingKey, "k")})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwt.PublicKey{Pub: &wrongKey.PublicKey, KID: "k"})

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); !errors.Is(err, jwt.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}
}

// TestVerifierUnknownKid confirms that an unknown kid is rejected.
func TestVerifierUnknownKid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "unknown-kid")})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "known-kid"})

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); !errors.Is(err, jwt.ErrUnknownKID) {
		t.Fatalf("expected ErrUnknownKID, got: %v", err)
	}
}

// TestVerifierIssMismatch confirms that a token with a mismatched iss is caught
// by the Validator, not the Verifier. Signature verification succeeds; the iss
// mismatch appears as a soft validation error.
func TestVerifierIssMismatch(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k")})

	claims := goodClaims()
	claims.Iss = "https://evil.example.com"
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "k"})

	// Decode+Verify succeeds - iss is not checked at the Verifier level.
	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); err != nil {
		t.Fatalf("Verify should succeed (no iss check): %v", err)
	}

	// VerifyJWT + Validate: signature passes but iss validation catches the mismatch.
	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("unexpected hard error from VerifyJWT: %v", err)
	}
	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	err = goodValidator().Validate(nil, &decoded, time.Now())
	if err == nil {
		t.Fatal("expected validation errors for iss mismatch")
	}
	if !errors.Is(err, jwt.ErrInvalidClaim) {
		t.Fatalf("expected ErrInvalidClaim for iss mismatch, got: %v", err)
	}
}

// TestVerifyTamperedAlg confirms that a tampered alg header ("none") is rejected.
// The token is reconstructed with a replaced protected header; the original
// ES256 signature is kept, making the signing input mismatch detectable.
func TestVerifyTamperedAlg(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k")})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "k"})

	// Replace the protected header with one that has alg:"none".
	// The original ES256 signature stays - the signing input will mismatch.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k","typ":"JWT"}`))
	parts := strings.SplitN(token, ".", 3)
	tamperedToken := noneHeader + "." + parts[1] + "." + parts[2]

	parsed, err := jwt.Decode(tamperedToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); !errors.Is(err, jwt.ErrUnsupportedAlg) {
		t.Fatalf("expected ErrUnsupportedAlg for tampered alg, got: %v", err)
	}
}

// TestSignerRoundTrip verifies the Signer / Sign / Verifier / Verify / Validate flow.
func TestSignerRoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k1")})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	iss := signer.Verifier()
	jws, err := iss.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jws.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if err := goodValidator().Validate(nil, &decoded, time.Now()); err != nil {
		t.Fatalf("claim validation failed: %v", err)
	}
	if decoded.Email != claims.Email {
		t.Errorf("email: got %s, want %s", decoded.Email, claims.Email)
	}
}

// TestSignerAutoKID verifies that KID is auto-computed from the key thumbprint
// when PrivateKey.KID is empty.
func TestSignerAutoKID(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "")})
	if err != nil {
		t.Fatal(err)
	}

	keys := signer.Keys
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KID == "" {
		t.Fatal("KID should be auto-computed from thumbprint")
	}

	// Token should verify with the auto-KID issuer.
	iss := signer.Verifier()
	claims := goodClaims()
	tokenStr, _ := signer.SignToString(&claims)

	parsed, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}
}

// TestSignerRoundRobin verifies that signing round-robins across keys and that
// all resulting tokens verify with the combined Verifier.
func TestSignerRoundRobin(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{
		mustPK(t, key1, "k1"),
		mustPK(t, key2, "k2"),
	})
	if err != nil {
		t.Fatal(err)
	}

	iss := signer.Verifier()
	v := goodValidator()

	for i := range 4 {
		claims := goodClaims()
		tokenStr, err := signer.SignToString(&claims)
		if err != nil {
			t.Fatalf("Sign[%d] failed: %v", i, err)
		}
		jws, err := iss.VerifyJWT(tokenStr)
		if err != nil {
			t.Fatalf("VerifyJWT[%d] failed: %v", i, err)
		}
		var decoded AppClaims
		if err := jws.UnmarshalClaims(&decoded); err != nil {
			t.Fatalf("UnmarshalClaims[%d] failed: %v", i, err)
		}
		if err := v.Validate(nil, &decoded, time.Now()); err != nil {
			t.Fatalf("Validate[%d] failed: %v", i, err)
		}
	}
}

// TestSignJWTSelectsByKID verifies that when the header already has a KID,
// SignJWT uses that specific key instead of round-robin.
func TestSignJWTSelectsByKID(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	key2, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{
		mustPK(t, key1, "ec256"),
		mustPK(t, key2, "ec384"),
	})
	if err != nil {
		t.Fatal(err)
	}

	// Request signing with key2 specifically by setting KID in the header.
	claims := &jwt.TokenClaims{
		Iss: "https://example.com",
		Sub: "user-1",
		Aud: jwt.Listish{"app"},
		Exp: time.Now().Add(time.Hour).Unix(),
		IAt: time.Now().Unix(),
	}
	jws, err := jwt.New(claims)
	if err != nil {
		t.Fatal(err)
	}
	jws.SetTyp("JWT")
	// Pre-set the KID to select key2.
	hdr := jws.GetHeader()
	hdr.KID = "ec384"
	if err := jws.SetHeader(&hdr); err != nil {
		t.Fatal(err)
	}

	if err := signer.SignJWT(jws); err != nil {
		t.Fatal(err)
	}

	// Should have used ES384, not ES256.
	if got := jws.GetHeader().Alg; got != "ES384" {
		t.Fatalf("alg: got %s, want ES384 (should have selected key2)", got)
	}
	if got := jws.GetHeader().KID; got != "ec384" {
		t.Fatalf("kid: got %s, want ec384", got)
	}

	// Verify round-trip.
	verifier := signer.Verifier()
	tokenStr, err := jwt.Encode(jws)
	if err != nil {
		t.Fatal(err)
	}
	parsed, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(parsed); err != nil {
		t.Fatalf("Verify: %v", err)
	}
}

// TestSignJWTUnknownKID verifies that SignJWT returns ErrUnknownKID when the
// header requests a KID that the signer doesn't have.
func TestSignJWTUnknownKID(t *testing.T) {
	key1, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, key1, "k1")})

	claims := &jwt.TokenClaims{
		Iss: "https://example.com",
		Sub: "user-1",
		Aud: jwt.Listish{"app"},
		Exp: time.Now().Add(time.Hour).Unix(),
		IAt: time.Now().Unix(),
	}
	jws, _ := jwt.New(claims)
	hdr := jws.GetHeader()
	hdr.KID = "nonexistent"
	_ = jws.SetHeader(&hdr)

	err := signer.SignJWT(jws)
	if !errors.Is(err, jwt.ErrUnknownKID) {
		t.Fatalf("expected ErrUnknownKID, got: %v", err)
	}
}

// TestJWKsRoundTrip verifies JWKS serialization and round-trip parsing.
func TestJWKsRoundTrip(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k1")})
	if err != nil {
		t.Fatal(err)
	}

	jwksBytes, err := json.Marshal(signer)
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip: parse the JWKS JSON and verify it produces a working Verifier.
	var jwks jwt.WellKnownJWKs
	if err := json.Unmarshal(jwksBytes, &jwks); err != nil {
		t.Fatal(err)
	}
	keys := jwks.Keys
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KID != "k1" {
		t.Errorf("expected kid 'k1', got %q", keys[0].KID)
	}

	iss2, _ := jwt.NewVerifier(keys)
	claims := goodClaims()
	tokenStr, _ := signer.SignToString(&claims)

	parsed, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss2.Verify(parsed); err != nil {
		t.Fatalf("Verify on round-tripped JWKS failed: %v", err)
	}
}

// TestKeyType verifies that KeyType returns the correct JWK kty string for each key type.
func TestKeyType(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name    string
		key     jwt.PublicKey
		wantKty string
	}{
		{"EC P-256", jwt.PublicKey{Pub: &ecKey.PublicKey}, "EC"},
		{"RSA 2048", jwt.PublicKey{Pub: &rsaKey.PublicKey}, "RSA"},
		{"Ed25519", jwt.PublicKey{Pub: edPub}, "OKP"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.key.KeyType(); got != tt.wantKty {
				t.Errorf("KeyType() = %q, want %q", got, tt.wantKty)
			}
		})
	}
}

// TestPublicKeyOps verifies that PrivateKey.PublicKey() translates key_ops to their
// public-key counterparts ("sign"=>"verify", "decrypt"=>"encrypt", "unwrapKey"=>"wrapKey").
func TestPublicKeyOps(t *testing.T) {
	tests := []struct {
		name       string
		privateOps []string
		wantOps    []string
	}{
		{"sign=>verify", []string{"sign"}, []string{"verify"}},
		{"decrypt=>encrypt", []string{"decrypt"}, []string{"encrypt"}},
		{"unwrapKey=>wrapKey", []string{"unwrapKey"}, []string{"wrapKey"}},
		{"multiple", []string{"sign", "decrypt"}, []string{"verify", "encrypt"}},
		{"public op passthrough", []string{"verify"}, []string{"verify"}},
		{"no public equivalent dropped", []string{"deriveKey"}, nil},
		{"empty", nil, nil},
	}
	base, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pk := *base
			pk.KeyOps = tt.privateOps
			pub, err := pk.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if len(pub.KeyOps) != len(tt.wantOps) {
				t.Fatalf("KeyOps = %v, want %v", pub.KeyOps, tt.wantOps)
			}
			for i, op := range pub.KeyOps {
				if op != tt.wantOps[i] {
					t.Errorf("KeyOps[%d] = %q, want %q", i, op, tt.wantOps[i])
				}
			}
		})
	}
}

// TestDecodePublicJWKJSON verifies JWKS JSON parsing with real base64url-encoded
// key material from RFC 7517 / OIDC examples.
func TestDecodePublicJWKJSON(t *testing.T) {
	jwksJSON := []byte(`{"keys":[
		{"kty":"EC","crv":"P-256",
		 "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		 "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		 "kid":"ec-256","use":"sig"},
		{"kty":"RSA",
		 "n":"0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc_BJECPebWKRXjBZCiFV4n3oknjhMstn64tZ_2W-5JsGY4Hc5n9yBXArwl93lqt7_RN5w6Cf0h4QyQ5v-65YGjQR0_FDW2QvzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbISD08qNLyrdkt-bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ-G_xBniIqbw0Ls1jF44-csFCur-kEgU8awapJzKnqDKgw",
		 "e":"AQAB","kid":"rsa-2048","use":"sig"}
	]}`)

	var jwks jwt.WellKnownJWKs
	if err := json.Unmarshal(jwksJSON, &jwks); err != nil {
		t.Fatal(err)
	}
	keys := jwks.Keys
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	var ecCount, rsaCount int
	for _, k := range keys {
		switch k.KeyType() {
		case "EC":
			ecCount++
			if k.KID != "ec-256" {
				t.Errorf("unexpected EC kid: %s", k.KID)
			}
		case "RSA":
			rsaCount++
			if k.KID != "rsa-2048" {
				t.Errorf("unexpected RSA kid: %s", k.KID)
			}
		}
	}
	if ecCount != 1 {
		t.Errorf("expected 1 EC key, got %d", ecCount)
	}
	if rsaCount != 1 {
		t.Errorf("expected 1 RSA key, got %d", rsaCount)
	}
}

// TestThumbprint verifies that Thumbprint returns a non-empty base64url string
// for EC, RSA, and Ed25519 keys, and that two equal keys produce the same thumbprint.
func TestThumbprint(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	tests := []struct {
		name string
		pub  jwt.PublicKey
	}{
		{"EC P-256", jwt.PublicKey{Pub: &ecKey.PublicKey}},
		{"RSA 2048", jwt.PublicKey{Pub: &rsaKey.PublicKey}},
		{"Ed25519", jwt.PublicKey{Pub: edPub}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thumb, err := tt.pub.Thumbprint()
			if err != nil {
				t.Fatalf("Thumbprint() error: %v", err)
			}
			if thumb == "" {
				t.Fatal("Thumbprint() returned empty string")
			}
			// Must be valid base64url (no padding, no +/)
			if strings.Contains(thumb, "+") || strings.Contains(thumb, "/") || strings.Contains(thumb, "=") {
				t.Errorf("Thumbprint() contains non-base64url characters: %s", thumb)
			}
			// Same key, same thumbprint
			thumb2, _ := tt.pub.Thumbprint()
			if thumb != thumb2 {
				t.Errorf("Thumbprint() not deterministic: %s != %s", thumb, thumb2)
			}
		})
	}
}

// TestNoKidAutoThumbprint verifies that a JWKS key without a "kid" field gets
// its KID auto-populated from the RFC 7638 thumbprint.
func TestNoKidAutoThumbprint(t *testing.T) {
	// EC key with no "kid" field in the JWKS
	jwksJSON := []byte(`{"keys":[
		{"kty":"EC","crv":"P-256",
		 "x":"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4",
		 "y":"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM",
		 "use":"sig"}
	]}`)

	var jwks jwt.WellKnownJWKs
	if err := json.Unmarshal(jwksJSON, &jwks); err != nil {
		t.Fatal(err)
	}
	keys := jwks.Keys
	if len(keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(keys))
	}
	if keys[0].KID == "" {
		t.Fatal("KID should be auto-populated from Thumbprint when absent in JWKS")
	}

	// The auto-KID should be a valid base64url string.
	kid := keys[0].KID
	if strings.Contains(kid, "+") || strings.Contains(kid, "/") || strings.Contains(kid, "=") {
		t.Errorf("auto-KID contains non-base64url characters: %s", kid)
	}

	// Round-trip: compute Thumbprint directly and compare.
	thumb, err := keys[0].Thumbprint()
	if err != nil {
		t.Fatalf("Thumbprint() error: %v", err)
	}
	if kid != thumb {
		t.Errorf("auto-KID %q != direct Thumbprint %q", kid, thumb)
	}
}

// TestNewPrivateKey verifies that jwt.NewPrivateKey generates an Ed25519 key
// with a non-empty KID auto-derived from the thumbprint, and that the key
// works end-to-end for signing and verification.
func TestNewPrivateKey(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error: %v", err)
	}
	if pk.KID == "" {
		t.Fatal("NewPrivateKey() returned empty KID")
	}
	// KID must be base64url (no +, /, or =).
	if strings.Contains(pk.KID, "+") || strings.Contains(pk.KID, "/") || strings.Contains(pk.KID, "=") {
		t.Errorf("KID contains non-base64url characters: %s", pk.KID)
	}
	// Two calls must produce different keys but always produce valid base64url KIDs.
	pk2, _ := jwt.NewPrivateKey()
	if pk.KID == pk2.KID {
		t.Error("NewPrivateKey() produced identical KIDs for two different keys")
	}

	// Full sign+verify round-trip with the generated key.
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatalf("SignToString() error: %v", err)
	}
	iss := signer.Verifier()
	jws, err := iss.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("VerifyJWT() error: %v", err)
	}
	var decoded AppClaims
	if err := jws.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims() error: %v", err)
	}
	if decoded.Sub != claims.Sub {
		t.Errorf("sub: got %q, want %q", decoded.Sub, claims.Sub)
	}
}

// --- DecodeRaw + UnmarshalHeader tests ---

func TestDecodeRaw(t *testing.T) {
	// Sign a real token to get a valid compact string.
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error: %v", err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatalf("SignToString() error: %v", err)
	}

	raw, err := jwt.DecodeRaw(tokenStr)
	if err != nil {
		t.Fatalf("DecodeRaw() error: %v", err)
	}

	// protected and payload should be non-empty base64url segments.
	if len(raw.GetProtected()) == 0 {
		t.Error("GetProtected() is empty")
	}
	if len(raw.GetPayload()) == 0 {
		t.Error("GetPayload() is empty")
	}
	if len(raw.GetSignature()) == 0 {
		t.Error("GetSignature() is empty")
	}
}

func TestDecodeRawErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		sentinel error
	}{
		{"empty string", "", jwt.ErrMalformedToken},
		{"one segment", "abc", jwt.ErrMalformedToken},
		{"two segments", "abc.def", jwt.ErrMalformedToken},
		{"four segments", "a.b.c.d", jwt.ErrMalformedToken},
		{"bad signature base64", "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ4In0.!!!bad!!!", jwt.ErrSignatureInvalid},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := jwt.DecodeRaw(tc.input)
			if err == nil {
				t.Fatal("expected error, got nil")
			}
			if !errors.Is(err, tc.sentinel) {
				t.Errorf("expected %v, got: %v", tc.sentinel, err)
			}
		})
	}
}

func TestDecodeRawSegmentCount(t *testing.T) {
	_, err := jwt.DecodeRaw("")
	if err == nil {
		t.Fatal("expected error")
	}
	// Empty string normalizes to 0 segments.
	if !strings.Contains(err.Error(), "got 0") {
		t.Errorf("expected segment count 0 in error, got: %v", err)
	}

	_, err = jwt.DecodeRaw("a.b")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "got 2") {
		t.Errorf("expected segment count 2 in error, got: %v", err)
	}
}

func TestUnmarshalHeader(t *testing.T) {
	// Sign a token and use DecodeRaw + UnmarshalHeader to recover the header.
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error: %v", err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatalf("SignToString() error: %v", err)
	}

	raw, err := jwt.DecodeRaw(tokenStr)
	if err != nil {
		t.Fatalf("DecodeRaw() error: %v", err)
	}

	var h jwt.RFCHeader
	if err := raw.UnmarshalHeader(&h); err != nil {
		t.Fatalf("UnmarshalHeader() error: %v", err)
	}

	if h.Alg != "EdDSA" {
		t.Errorf("alg: got %q, want %q", h.Alg, "EdDSA")
	}
	if h.KID != pk.KID {
		t.Errorf("kid: got %q, want %q", h.KID, pk.KID)
	}
	if h.Typ != "JWT" {
		t.Errorf("typ: got %q, want %q", h.Typ, "JWT")
	}
}

func TestUnmarshalHeaderCustomFields(t *testing.T) {
	// Build a token whose header has a custom "nonce" field by constructing
	// the compact string manually: base64(header).base64(payload).base64(sig).
	type CustomHeader struct {
		jwt.RFCHeader
		Nonce string `json:"nonce"`
	}

	hdr := CustomHeader{
		RFCHeader: jwt.RFCHeader{Alg: "EdDSA", KID: "test-key", Typ: "dpop+jwt"},
		Nonce:     "server-nonce-42",
	}
	hdrJSON, _ := json.Marshal(hdr)
	payJSON := []byte(`{"sub":"user"}`)
	fakeSig := []byte{0xDE, 0xAD}

	compact := base64.RawURLEncoding.EncodeToString(hdrJSON) +
		"." + base64.RawURLEncoding.EncodeToString(payJSON) +
		"." + base64.RawURLEncoding.EncodeToString(fakeSig)

	raw, err := jwt.DecodeRaw(compact)
	if err != nil {
		t.Fatalf("DecodeRaw() error: %v", err)
	}

	var got CustomHeader
	if err := raw.UnmarshalHeader(&got); err != nil {
		t.Fatalf("UnmarshalHeader() error: %v", err)
	}

	if got.Nonce != "server-nonce-42" {
		t.Errorf("nonce: got %q, want %q", got.Nonce, "server-nonce-42")
	}
	if got.Alg != "EdDSA" {
		t.Errorf("alg: got %q, want %q", got.Alg, "EdDSA")
	}
	if got.Typ != "dpop+jwt" {
		t.Errorf("typ: got %q, want %q", got.Typ, "dpop+jwt")
	}
}

func TestUnmarshalHeaderViaJWS(t *testing.T) {
	// Verify that UnmarshalHeader is promoted from RawJWT to *JWT.
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error: %v", err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatalf("SignToString() error: %v", err)
	}

	// Use Decode (not DecodeRaw) - UnmarshalHeader should still work via promotion.
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	var h jwt.RFCHeader
	if err := jws.UnmarshalHeader(&h); err != nil {
		t.Fatalf("jws.UnmarshalHeader() error: %v", err)
	}
	if h.Alg != "EdDSA" {
		t.Errorf("alg: got %q, want %q", h.Alg, "EdDSA")
	}
}

// --- SpaceDelimited tests ---

func TestSpaceDelimitedMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		in   jwt.SpaceDelimited
		want string
	}{
		{"multiple", jwt.SpaceDelimited{"openid", "profile", "email"}, `"openid profile email"`},
		{"single", jwt.SpaceDelimited{"openid"}, `"openid"`},
		{"empty", jwt.SpaceDelimited{}, `""`},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.in)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("got %s, want %s", got, tt.want)
			}
		})
	}
}

func TestSpaceDelimitedUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    jwt.SpaceDelimited
		wantNil bool
	}{
		{"multiple", `"openid profile email"`, jwt.SpaceDelimited{"openid", "profile", "email"}, false},
		{"single", `"openid"`, jwt.SpaceDelimited{"openid"}, false},
		{"empty", `""`, jwt.SpaceDelimited{}, false},
		{"extra whitespace", `"openid  profile\temail"`, jwt.SpaceDelimited{"openid", "profile", "email"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got jwt.SpaceDelimited
			if err := json.Unmarshal([]byte(tt.in), &got); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}
			if tt.wantNil {
				if got != nil {
					t.Errorf("got %v, want nil", got)
				}
				return
			}
			if len(got) != len(tt.want) {
				t.Fatalf("got %v (len %d), want %v (len %d)", got, len(got), tt.want, len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d] = %q, want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func TestSpaceDelimitedRoundTrip(t *testing.T) {
	type claims struct {
		Scope jwt.SpaceDelimited `json:"scope,omitempty"`
	}
	orig := claims{Scope: jwt.SpaceDelimited{"openid", "profile"}}
	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}

	// Verify wire format is a space-separated string.
	if !strings.Contains(string(data), `"openid profile"`) {
		t.Fatalf("expected space-separated scope in JSON, got %s", data)
	}

	var decoded claims
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Scope) != 2 || decoded.Scope[0] != "openid" || decoded.Scope[1] != "profile" {
		t.Errorf("round-trip failed: got %v", decoded.Scope)
	}
}

// --- SetTyp / NewAccessToken tests ---

func TestSetTyp(t *testing.T) {
	claims := &jwt.TokenClaims{
		Iss: "https://example.com",
		Sub: "user1",
		Aud: jwt.Listish{"api"},
		Exp: time.Now().Add(time.Hour).Unix(),
		IAt: time.Now().Unix(),
	}
	jws, err := jwt.New(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Default typ is "JWT".
	if got := jws.GetHeader().Typ; got != "JWT" {
		t.Fatalf("default typ: got %q, want %q", got, "JWT")
	}

	jws.SetTyp(jwt.AccessTokenTyp)

	if got := jws.GetHeader().Typ; got != jwt.AccessTokenTyp {
		t.Fatalf("after SetTyp: got %q, want %q", got, jwt.AccessTokenTyp)
	}
}

func TestSetTypSurvivesSigning(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, priv, "")})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss:      "https://auth.example.com",
		Sub:      "user1",
		Aud:      jwt.Listish{"https://api.example.com"},
		Exp:      now.Add(time.Hour).Unix(),
		IAt:      now.Unix(),
		JTI:      "tok-001",
		ClientID: "webapp",
		Scope:    jwt.SpaceDelimited{"openid", "profile"},
	}

	jws, err := jwt.NewAccessToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SignJWT(jws); err != nil {
		t.Fatal(err)
	}

	// Verify typ survived signing.
	if got := jws.GetHeader().Typ; got != jwt.AccessTokenTyp {
		t.Fatalf("typ after signing: got %q, want %q", got, jwt.AccessTokenTyp)
	}

	// Decode the token and verify typ is in the wire format.
	token, err := jwt.Encode(jws)
	if err != nil {
		t.Fatalf("Encode failed: %v", err)
	}
	decoded, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.GetHeader().Typ; got != jwt.AccessTokenTyp {
		t.Fatalf("typ after decode: got %q, want %q", got, jwt.AccessTokenTyp)
	}

	// Verify claims round-trip.
	var rt jwt.TokenClaims
	if err := decoded.UnmarshalClaims(&rt); err != nil {
		t.Fatal(err)
	}
	if rt.ClientID != "webapp" {
		t.Errorf("client_id: got %q, want %q", rt.ClientID, "webapp")
	}
	if len(rt.Scope) != 2 || rt.Scope[0] != "openid" {
		t.Errorf("scope: got %v, want [openid profile]", rt.Scope)
	}
}

// --- Access token Validator tests ---

func goodAccessTokenClaims() *jwt.TokenClaims {
	now := time.Now()
	return &jwt.TokenClaims{
		Iss:      "https://auth.example.com",
		Sub:      "user1",
		Aud:      jwt.Listish{"https://api.example.com"},
		Exp:      now.Add(time.Hour).Unix(),
		IAt:      now.Unix(),
		JTI:      "tok-001",
		ClientID: "webapp",
		Scope:    jwt.SpaceDelimited{"openid", "profile"},
		AMR:      []string{"pwd"},
	}
}

func TestAccessTokenValidatorHappyPath(t *testing.T) {
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	claims := goodAccessTokenClaims()
	if err := v.Validate(nil, claims, time.Now()); err != nil {
		t.Fatalf("valid access token rejected: %v", err)
	}
}

func TestAccessTokenValidatorRequiresJTI(t *testing.T) {
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	claims := goodAccessTokenClaims()
	claims.JTI = ""
	err := v.Validate(nil, claims, time.Now())
	if !errors.Is(err, jwt.ErrMissingClaim) {
		t.Fatalf("expected ErrMissingClaim for missing jti, got: %v", err)
	}
}

func TestAccessTokenValidatorRequiresClientID(t *testing.T) {
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	claims := goodAccessTokenClaims()
	claims.ClientID = ""
	err := v.Validate(nil, claims, time.Now())
	if !errors.Is(err, jwt.ErrMissingClaim) {
		t.Fatalf("expected ErrMissingClaim for missing client_id, got: %v", err)
	}
}

func TestAccessTokenValidatorDisableClientID(t *testing.T) {
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	v.Checks &^= jwt.CheckClientID
	claims := goodAccessTokenClaims()
	claims.ClientID = ""
	if err := v.Validate(nil, claims, time.Now()); err != nil {
		t.Fatalf("disabling CheckClientID should accept empty client_id: %v", err)
	}
}

func TestAccessTokenValidatorExpiredToken(t *testing.T) {
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	claims := goodAccessTokenClaims()
	claims.Exp = time.Now().Add(-time.Hour).Unix()
	err := v.Validate(nil, claims, time.Now())
	if !errors.Is(err, jwt.ErrAfterExp) {
		t.Fatalf("expected ErrAfterExp, got: %v", err)
	}
}

func TestAccessTokenValidatorRequiredScopes(t *testing.T) {
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	v.RequiredScopes = []string{"openid", "admin"}
	claims := goodAccessTokenClaims()
	// claims has ["openid", "profile"] - missing "admin"
	err := v.Validate(nil, claims, time.Now())
	if !errors.Is(err, jwt.ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope for missing scope, got: %v", err)
	}
}

func TestAccessTokenValidatorExpectScope(t *testing.T) {
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	v.Checks |= jwt.CheckScope // enable scope presence check
	claims := goodAccessTokenClaims()
	claims.Scope = nil
	err := v.Validate(nil, claims, time.Now())
	if !errors.Is(err, jwt.ErrMissingClaim) {
		t.Fatalf("expected ErrMissingClaim for empty scope, got: %v", err)
	}
}

func TestAccessTokenValidatorDisableJTI(t *testing.T) {
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	v.Checks &^= jwt.CheckJTI
	claims := goodAccessTokenClaims()
	claims.JTI = ""
	if err := v.Validate(nil, claims, time.Now()); err != nil {
		t.Fatalf("disabling CheckJTI should accept empty jti: %v", err)
	}
}

// --- Encode validation tests ---

// stubJWT is a minimal VerifiableJWT for testing Encode validation.
type stubJWT struct {
	protected []byte
	payload   []byte
	signature []byte
	header    jwt.RFCHeader
}

func (s *stubJWT) GetProtected() []byte     { return s.protected }
func (s *stubJWT) GetPayload() []byte       { return s.payload }
func (s *stubJWT) GetSignature() []byte     { return s.signature }
func (s *stubJWT) GetHeader() jwt.RFCHeader { return s.header }

// TestEncodeRejectsEmptyAlg verifies that Encode returns an error
// when the alg header field is empty (unsigned token).
func TestEncodeRejectsEmptyAlg(t *testing.T) {
	// Zero-value stub: no alg set.
	jws := &stubJWT{}
	_, err := jwt.Encode(jws)
	if err == nil {
		t.Fatal("expected error for empty alg")
	}
	if !errors.Is(err, jwt.ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader, got: %v", err)
	}
	if !strings.Contains(err.Error(), "alg is empty") {
		t.Fatalf("unexpected message: %v", err)
	}

	// Explicit header with typ but no alg.
	jws2 := &stubJWT{
		protected: []byte(base64.RawURLEncoding.EncodeToString([]byte(`{"typ":"JWT"}`))),
		payload:   []byte(base64.RawURLEncoding.EncodeToString([]byte(`{"sub":"user1"}`))),
		signature: []byte{0x01, 0x02, 0x03},
		header:    jwt.RFCHeader{Typ: "JWT"},
	}
	_, err = jwt.Encode(jws2)
	if err == nil {
		t.Fatal("expected error for empty alg with typ-only header")
	}
	if !errors.Is(err, jwt.ErrInvalidHeader) {
		t.Fatalf("expected ErrInvalidHeader, got: %v", err)
	}
}

// TestEncodeSucceedsAfterSigning verifies the happy path: a signed JWT
// encodes without error.
func TestEncodeSucceedsAfterSigning(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k1")})
	if err != nil {
		t.Fatal(err)
	}
	claims := goodClaims()
	jws, err := signer.Sign(&claims)
	if err != nil {
		t.Fatal(err)
	}

	token, err := jwt.Encode(jws)
	if err != nil {
		t.Fatalf("Encode failed on signed JWT: %v", err)
	}
	parts := strings.Split(token, ".")
	if len(parts) != 3 {
		t.Fatalf("expected 3 segments, got %d", len(parts))
	}
	for i, p := range parts {
		if p == "" {
			t.Fatalf("segment %d is empty", i)
		}
	}
}

// --- Full pipeline round-trip tests ---

// TestRoundTrip_IDToken exercises the full ID token pipeline:
// NewPrivateKey -> NewSigner -> SignToString -> Decode -> Verify -> UnmarshalClaims -> Validate.
func TestRoundTrip_IDToken(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss:      "https://idp.example.com",
		Sub:      "user-42",
		Aud:      jwt.Listish{"my-client"},
		Exp:      now.Add(time.Hour).Unix(),
		IAt:      now.Unix(),
		AuthTime: now.Unix(),
		AzP:      "my-client",
		Nonce:    "n-0S6_WzA2Mj",
		AMR:      []string{"pwd", "otp"},
		JTI:      "id-tok-001",
	}

	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Decode + Verify
	decoded, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	verifier := signer.Verifier()
	if err := verifier.Verify(decoded); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// UnmarshalClaims
	var got jwt.TokenClaims
	if err := decoded.UnmarshalClaims(&got); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}

	// Validate with NewIDTokenValidator
	v := jwt.NewIDTokenValidator(
		[]string{"https://idp.example.com"},
		[]string{"my-client"},
		[]string{"my-client"},
		0,
	)
	if err := v.Validate(nil, &got, time.Now()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Spot-check round-tripped fields.
	if got.Sub != "user-42" {
		t.Errorf("sub: got %q, want %q", got.Sub, "user-42")
	}
	if got.Nonce != "n-0S6_WzA2Mj" {
		t.Errorf("nonce: got %q, want %q", got.Nonce, "n-0S6_WzA2Mj")
	}
	if len(got.AMR) != 2 || got.AMR[0] != "pwd" || got.AMR[1] != "otp" {
		t.Errorf("amr: got %v, want [pwd otp]", got.AMR)
	}
}

// TestRoundTrip_AccessToken exercises the full access token pipeline:
// NewAccessToken -> SignJWT -> Encode -> Decode -> Verify -> UnmarshalClaims -> Validate with RequiredScopes.
func TestRoundTrip_AccessToken(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss:      "https://auth.example.com",
		Sub:      "svc-account",
		Aud:      jwt.Listish{"https://api.example.com"},
		Exp:      now.Add(time.Hour).Unix(),
		IAt:      now.Unix(),
		JTI:      "at-001",
		ClientID: "backend-svc",
		Scope:    jwt.SpaceDelimited{"read", "write", "admin"},
	}

	jws, err := jwt.NewAccessToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SignJWT(jws); err != nil {
		t.Fatal(err)
	}

	tokenStr, err := jwt.Encode(jws)
	if err != nil {
		t.Fatalf("Encode: %v", err)
	}

	// Decode + Verify
	decoded, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}

	// Verify typ survived the round-trip.
	if got := decoded.GetHeader().Typ; got != jwt.AccessTokenTyp {
		t.Errorf("typ: got %q, want %q", got, jwt.AccessTokenTyp)
	}

	verifier := signer.Verifier()
	if err := verifier.Verify(decoded); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	var got jwt.TokenClaims
	if err := decoded.UnmarshalClaims(&got); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}

	// Validate with RequiredScopes.
	v := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	v.RequiredScopes = []string{"read", "write"}
	if err := v.Validate(nil, &got, time.Now()); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	// Spot-check scope round-trip.
	if len(got.Scope) != 3 || got.Scope[0] != "read" || got.Scope[2] != "admin" {
		t.Errorf("scope: got %v, want [read write admin]", got.Scope)
	}
	if got.ClientID != "backend-svc" {
		t.Errorf("client_id: got %q, want %q", got.ClientID, "backend-svc")
	}
}

// TestRoundTrip_StandardClaims verifies that StandardClaims with NullBool fields
// survive the sign-decode round-trip.
func TestRoundTrip_StandardClaims(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.StandardClaims{
		TokenClaims: jwt.TokenClaims{
			Iss:      "https://idp.example.com",
			Sub:      "user-99",
			Aud:      jwt.Listish{"app"},
			Exp:      now.Add(time.Hour).Unix(),
			IAt:      now.Unix(),
			AuthTime: now.Unix(),
			AzP:      "app",
		},
		Name:                "Jane Doe",
		Email:               "jane@example.com",
		EmailVerified:       jwt.NullBool{Bool: true, Valid: true},
		PhoneNumber:         "+1-555-0100",
		PhoneNumberVerified: jwt.NullBool{Bool: false, Valid: true},
		Locale:              "en-US",
	}

	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Decode + Verify
	verifier := signer.Verifier()
	jws, err := verifier.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}

	var got jwt.StandardClaims
	if err := jws.UnmarshalClaims(&got); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}

	// Verify NullBool fields survived the round-trip.
	if !got.EmailVerified.Valid || !got.EmailVerified.Bool {
		t.Errorf("email_verified: got %+v, want {Bool:true Valid:true}", got.EmailVerified)
	}
	if !got.PhoneNumberVerified.Valid || got.PhoneNumberVerified.Bool {
		t.Errorf("phone_number_verified: got %+v, want {Bool:false Valid:true}", got.PhoneNumberVerified)
	}

	// Verify other profile fields.
	if got.Name != "Jane Doe" {
		t.Errorf("name: got %q, want %q", got.Name, "Jane Doe")
	}
	if got.Email != "jane@example.com" {
		t.Errorf("email: got %q, want %q", got.Email, "jane@example.com")
	}
	if got.Locale != "en-US" {
		t.Errorf("locale: got %q, want %q", got.Locale, "en-US")
	}

	// Verify that an unset NullBool (not in JSON) comes back as zero value.
	// StandardClaims has no field we explicitly omitted that is a NullBool
	// other than the two we set, so we create a fresh StandardClaims without
	// email_verified to test omission.
	claims2 := &jwt.StandardClaims{
		TokenClaims: jwt.TokenClaims{
			Iss:      "https://idp.example.com",
			Sub:      "user-100",
			Aud:      jwt.Listish{"app"},
			Exp:      now.Add(time.Hour).Unix(),
			IAt:      now.Unix(),
			AuthTime: now.Unix(),
			AzP:      "app",
		},
		Email: "bob@example.com",
		// EmailVerified left as zero value (NullBool{})
	}
	tok2, err := signer.SignToString(claims2)
	if err != nil {
		t.Fatal(err)
	}
	jws2, err := verifier.VerifyJWT(tok2)
	if err != nil {
		t.Fatal(err)
	}
	var got2 jwt.StandardClaims
	if err := jws2.UnmarshalClaims(&got2); err != nil {
		t.Fatal(err)
	}
	if got2.EmailVerified.Valid {
		t.Errorf("omitted email_verified should be invalid, got %+v", got2.EmailVerified)
	}
}

// --- DPoPJWT: custom header type used by TestRoundTrip_CustomHeader ---

// dpopHeader extends the standard JOSE header with a DPoP nonce.
type dpopHeader struct {
	jwt.RFCHeader
	Nonce string `json:"nonce,omitempty"`
}

// dpopJWT is a custom JWT that carries a dpopHeader.
type dpopJWT struct {
	jwt.RawJWT
	Header dpopHeader
}

func (d *dpopJWT) GetHeader() jwt.RFCHeader { return d.Header.RFCHeader }

func (d *dpopJWT) SetHeader(hdr jwt.Header) error {
	d.Header.RFCHeader = *hdr.GetRFCHeader()
	data, err := json.Marshal(d.Header)
	if err != nil {
		return err
	}
	d.Protected = []byte(base64.RawURLEncoding.EncodeToString(data))
	return nil
}

// TestRoundTrip_CustomHeader verifies that custom header fields survive the
// full sign-decode-verify round-trip when using a custom SignableJWT type.
func TestRoundTrip_CustomHeader(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}
	verifier := signer.Verifier()

	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss: "https://example.com",
		Sub: "user-1",
		Aud: jwt.Listish{"api"},
		Exp: now.Add(time.Hour).Unix(),
		IAt: now.Unix(),
	}

	// Build and sign a DPoP JWT with a custom nonce header.
	dpop := &dpopJWT{Header: dpopHeader{
		RFCHeader: jwt.RFCHeader{Typ: "dpop+jwt"},
		Nonce:     "server-nonce-abc",
	}}
	if err := dpop.SetClaims(claims); err != nil {
		t.Fatal(err)
	}
	if err := signer.SignJWT(dpop); err != nil {
		t.Fatal(err)
	}
	tokenStr, err := jwt.Encode(dpop)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the signature with the standard Decode path.
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	if err := verifier.Verify(jws); err != nil {
		t.Fatalf("Verify: %v", err)
	}

	// Recover the custom header via DecodeRaw + UnmarshalHeader.
	raw, err := jwt.DecodeRaw(tokenStr)
	if err != nil {
		t.Fatalf("DecodeRaw: %v", err)
	}
	var gotHdr dpopHeader
	if err := raw.UnmarshalHeader(&gotHdr); err != nil {
		t.Fatalf("UnmarshalHeader: %v", err)
	}

	if gotHdr.Nonce != "server-nonce-abc" {
		t.Errorf("nonce: got %q, want %q", gotHdr.Nonce, "server-nonce-abc")
	}
	if gotHdr.Typ != "dpop+jwt" {
		t.Errorf("typ: got %q, want %q", gotHdr.Typ, "dpop+jwt")
	}
	if gotHdr.Alg != "EdDSA" {
		t.Errorf("alg: got %q, want %q", gotHdr.Alg, "EdDSA")
	}
	if gotHdr.KID != pk.KID {
		t.Errorf("kid: got %q, want %q", gotHdr.KID, pk.KID)
	}
}

// TestRoundTrip_ExpiredTokenRejection signs a token with a past exp, verifies
// that Decode+Verify succeeds (signature is valid) but Validate rejects it.
func TestRoundTrip_ExpiredTokenRejection(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss:      "https://idp.example.com",
		Sub:      "user-1",
		Aud:      jwt.Listish{"app"},
		Exp:      now.Add(-time.Hour).Unix(), // expired 1 hour ago
		IAt:      now.Add(-2 * time.Hour).Unix(),
		AuthTime: now.Add(-2 * time.Hour).Unix(),
		AzP:      "app",
	}

	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Decode + Verify should succeed - the signature is valid.
	decoded, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatalf("Decode: %v", err)
	}
	verifier := signer.Verifier()
	if err := verifier.Verify(decoded); err != nil {
		t.Fatalf("Verify should succeed for expired token: %v", err)
	}

	var got jwt.TokenClaims
	if err := decoded.UnmarshalClaims(&got); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}

	// Validate should fail with ErrAfterExp.
	v := jwt.NewIDTokenValidator(
		[]string{"https://idp.example.com"},
		[]string{"app"},
		[]string{"app"},
		0,
	)
	err = v.Validate(nil, &got, time.Now())
	if err == nil {
		t.Fatal("expected validation error for expired token")
	}
	if !errors.Is(err, jwt.ErrAfterExp) {
		t.Fatalf("expected ErrAfterExp, got: %v", err)
	}
}

// TestRoundTrip_WrongAudienceRejection signs a token with one audience and
// validates against a different audience, expecting rejection.
func TestRoundTrip_WrongAudienceRejection(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss:      "https://idp.example.com",
		Sub:      "user-1",
		Aud:      jwt.Listish{"app-A"},
		Exp:      now.Add(time.Hour).Unix(),
		IAt:      now.Unix(),
		AuthTime: now.Unix(),
		AzP:      "app-A",
	}

	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Decode + Verify succeeds.
	verifier := signer.Verifier()
	jws, err := verifier.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("VerifyJWT: %v", err)
	}

	var got jwt.TokenClaims
	if err := jws.UnmarshalClaims(&got); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}

	// Validate with a different audience - should fail.
	v := jwt.NewIDTokenValidator(
		[]string{"https://idp.example.com"},
		[]string{"app-B"}, // wrong audience
		[]string{"app-A"},
		0,
	)
	err = v.Validate(nil, &got, time.Now())
	if err == nil {
		t.Fatal("expected validation error for wrong audience")
	}
	if !errors.Is(err, jwt.ErrInvalidClaim) {
		t.Fatalf("expected ErrInvalidClaim for aud mismatch, got: %v", err)
	}
}

// TestDuplicateKIDRotation verifies that when multiple keys share the same KID
// (e.g. during key rotation), the verifier tries all matching keys and succeeds
// if any one of them verifies the signature.
func TestDuplicateKIDRotation(t *testing.T) {
	oldKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	newKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Both keys share the same KID (simulating a rotation where the KID is reused).
	sharedKID := "rotating-key"

	// Sign a token with the OLD key.
	oldSigner, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, oldKey, sharedKID)})
	if err != nil {
		t.Fatal(err)
	}
	claims := goodClaims()
	oldToken, err := oldSigner.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	// Sign a token with the NEW key.
	newSigner, err := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, newKey, sharedKID)})
	if err != nil {
		t.Fatal(err)
	}
	newToken, err := newSigner.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	// Verifier has both keys under the same KID.
	verifier, err := jwt.NewVerifier([]jwt.PublicKey{
		{Pub: &oldKey.PublicKey, KID: sharedKID},
		{Pub: &newKey.PublicKey, KID: sharedKID},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Both tokens should verify successfully.
	for _, tt := range []struct {
		name  string
		token string
	}{
		{"old key", oldToken},
		{"new key", newToken},
	} {
		t.Run(tt.name, func(t *testing.T) {
			parsed, err := jwt.Decode(tt.token)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if err := verifier.Verify(parsed); err != nil {
				t.Fatalf("Verify should succeed for %s: %v", tt.name, err)
			}
		})
	}
}

// TestNoKIDTriesAllKeys verifies that when a token has no KID, all verifier
// keys are tried and the first successful verification wins.
func TestNoKIDTriesAllKeys(t *testing.T) {
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rightKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Sign with rightKey using SignRaw with a header that has no KID.
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, rightKey, "any")})
	hdr := &jwt.RFCHeader{} // no KID, no typ
	payloadJSON := []byte(`{"sub":"user-1"}`)
	raw, err := signer.SignRaw(hdr, payloadJSON)
	if err != nil {
		t.Fatal(err)
	}

	// Reconstruct as compact token: protected.payload.signature
	token := string(raw.GetProtected()) + "." + string(raw.GetPayload()) +
		"." + base64.RawURLEncoding.EncodeToString(raw.GetSignature())

	// Verifier has wrongKey first, then rightKey.
	verifier, err := jwt.NewVerifier([]jwt.PublicKey{
		{Pub: &wrongKey.PublicKey, KID: "wrong"},
		{Pub: &rightKey.PublicKey, KID: "right"},
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.GetHeader().KID != "" {
		t.Fatalf("token should have no KID, got %q", parsed.GetHeader().KID)
	}
	if err := verifier.Verify(parsed); err != nil {
		t.Fatalf("Verify should try all keys when token has no KID: %v", err)
	}
}

// TestEmptyKIDTokenEmptyKIDKey verifies that when both the token and a
// verifier key have empty KIDs, verification succeeds (all keys are tried).
func TestEmptyKIDTokenEmptyKIDKey(t *testing.T) {
	rightKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Sign with SignRaw to produce a token with no KID.
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, rightKey, "any")})
	raw, err := signer.SignRaw(&jwt.RFCHeader{}, []byte(`{"sub":"user-1"}`))
	if err != nil {
		t.Fatal(err)
	}
	token := string(raw.GetProtected()) + "." + string(raw.GetPayload()) +
		"." + base64.RawURLEncoding.EncodeToString(raw.GetSignature())

	// Verifier key also has empty KID.
	verifier, err := jwt.NewVerifier([]jwt.PublicKey{
		{Pub: &rightKey.PublicKey, KID: ""},
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(parsed); err != nil {
		t.Fatalf("empty KID token + empty KID key should verify: %v", err)
	}
}

// TestKIDTokenEmptyKIDKey verifies that when the token has a KID but the
// verifier key has an empty KID, the key is not a candidate (no match).
func TestKIDTokenEmptyKIDKey(t *testing.T) {
	rightKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Sign normally -- token gets a KID from the signer.
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, rightKey, "my-kid")})
	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	// Verifier has the same key material but with an empty KID.
	verifier, err := jwt.NewVerifier([]jwt.PublicKey{
		{Pub: &rightKey.PublicKey, KID: ""},
	})
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	err = verifier.Verify(parsed)
	if !errors.Is(err, jwt.ErrUnknownKID) {
		t.Fatalf("token KID %q should not match empty-KID key, expected ErrUnknownKID, got: %v",
			parsed.GetHeader().KID, err)
	}
}

// TestMultiKeyVerifier verifies that a Verifier with keys of different algorithms
// correctly selects the right key by KID when verifying tokens.
func TestMultiKeyVerifier(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, edPriv, _ := ed25519.GenerateKey(rand.Reader)

	ecPK := mustPK(t, ecKey, "ec-key")
	rsaPK := mustPK(t, rsaKey, "rsa-key")
	edPK := mustPK(t, edPriv, "ed-key")

	// Create a verifier with all three public keys.
	verifier, err := jwt.NewVerifier([]jwt.PublicKey{
		{Pub: &ecKey.PublicKey, KID: "ec-key"},
		{Pub: &rsaKey.PublicKey, KID: "rsa-key"},
		{Pub: edPub, KID: "ed-key"},
	})
	if err != nil {
		t.Fatal(err)
	}

	// Sign a token with each key type and verify the multi-key verifier picks the right one.
	for _, tt := range []struct {
		name string
		pk   *jwt.PrivateKey
		alg  string
	}{
		{"EC/ES256", ecPK, "ES256"},
		{"RSA/RS256", rsaPK, "RS256"},
		{"Ed25519/EdDSA", edPK, "EdDSA"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			signer, err := jwt.NewSigner([]*jwt.PrivateKey{tt.pk})
			if err != nil {
				t.Fatal(err)
			}
			claims := goodClaims()
			tokenStr, err := signer.SignToString(&claims)
			if err != nil {
				t.Fatal(err)
			}

			parsed, err := jwt.Decode(tokenStr)
			if err != nil {
				t.Fatalf("Decode: %v", err)
			}
			if parsed.GetHeader().Alg != tt.alg {
				t.Fatalf("alg: got %s, want %s", parsed.GetHeader().Alg, tt.alg)
			}
			if err := verifier.Verify(parsed); err != nil {
				t.Fatalf("Verify failed for %s: %v", tt.alg, err)
			}
		})
	}
}

// TestAudienceSingleString verifies that a single-string "aud" claim
// (RFC 7519 §4.1.3) is correctly unmarshaled as a single-element Audience.
func TestAudienceSingleString(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss:      "https://example.com",
		Sub:      "user-1",
		Aud:      jwt.Listish{"single-aud"}, // single element
		Exp:      now.Add(time.Hour).Unix(),
		IAt:      now.Unix(),
		AuthTime: now.Unix(),
	}

	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	// Verify the wire format uses a string (not an array) for single-element aud.
	decoded, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	var rawPayload map[string]json.RawMessage
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(string(decoded.GetPayload()))
	if err := json.Unmarshal(payloadBytes, &rawPayload); err != nil {
		t.Fatal(err)
	}
	audRaw := string(rawPayload["aud"])
	if audRaw[0] == '[' {
		t.Errorf("single-element aud should be a string, got array: %s", audRaw)
	}

	// Unmarshal and validate.
	var got jwt.TokenClaims
	if err := decoded.UnmarshalClaims(&got); err != nil {
		t.Fatal(err)
	}
	if len(got.Aud) != 1 || got.Aud[0] != "single-aud" {
		t.Errorf("aud: got %v, want [single-aud]", got.Aud)
	}

	// Also test unmarshaling from a manually constructed single-string aud.
	singleJSON := []byte(`"just-one"`)
	var aud jwt.Listish
	if err := json.Unmarshal(singleJSON, &aud); err != nil {
		t.Fatalf("Unmarshal single-string aud: %v", err)
	}
	if len(aud) != 1 || aud[0] != "just-one" {
		t.Errorf("single-string unmarshal: got %v, want [just-one]", aud)
	}

	// And array form.
	arrayJSON := []byte(`["a","b"]`)
	var aud2 jwt.Listish
	if err := json.Unmarshal(arrayJSON, &aud2); err != nil {
		t.Fatalf("Unmarshal array aud: %v", err)
	}
	if len(aud2) != 2 || aud2[0] != "a" || aud2[1] != "b" {
		t.Errorf("array unmarshal: got %v, want [a b]", aud2)
	}
}

// TestVerifyTamperedPayload confirms that a tampered payload (modified after signing)
// is rejected by signature verification.
func TestVerifyTamperedPayload(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{mustPK(t, privKey, "k")})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	verifier := goodVerifier(jwt.PublicKey{Pub: &privKey.PublicKey, KID: "k"})

	// Tamper with the payload: change the sub claim.
	parts := strings.SplitN(token, ".", 3)
	payloadBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	tampered := strings.Replace(string(payloadBytes), claims.Sub, "evil-user", 1)
	parts[1] = base64.RawURLEncoding.EncodeToString([]byte(tampered))
	tamperedToken := strings.Join(parts, ".")

	parsed, err := jwt.Decode(tamperedToken)
	if err != nil {
		t.Fatalf("Decode should succeed for well-formed tampered token: %v", err)
	}
	if err := verifier.Verify(parsed); err == nil {
		t.Fatal("expected Verify to fail for tampered payload")
	} else if !errors.Is(err, jwt.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}
}

// TestValidationErrorAnnotation verifies that time-related validation errors
// include the server time annotation.
func TestValidationErrorAnnotation(t *testing.T) {
	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss:      "https://example.com",
		Sub:      "user-1",
		Aud:      jwt.Listish{"app"},
		Exp:      now.Add(-time.Hour).Unix(), // expired
		IAt:      now.Unix(),
		AuthTime: now.Unix(),
	}

	v := jwt.NewIDTokenValidator(
		[]string{"https://example.com"},
		[]string{"app"},
		nil,
		0,
	)
	err := v.Validate(nil, claims, now)
	if err == nil {
		t.Fatal("expected validation error")
	}
	if !strings.Contains(err.Error(), "server time") {
		t.Errorf("time error should include server time annotation: %v", err)
	}
}

// TestValidateThreadsHeaderErrors verifies that errors from header validation
// (IsAllowedTyp) are preserved when threaded into Validate.
func TestValidateThreadsHeaderErrors(t *testing.T) {
	now := time.Now()
	claims := &jwt.TokenClaims{
		Iss:      "https://example.com",
		Sub:      "user-1",
		Aud:      jwt.Listish{"app"},
		Exp:      now.Add(time.Hour).Unix(),
		IAt:      now.Unix(),
		AuthTime: now.Unix(),
	}

	v := jwt.NewIDTokenValidator(
		[]string{"https://example.com"},
		[]string{"app"},
		nil,
		0,
	)

	// Simulate a header check failure.
	hdr := jwt.RFCHeader{Typ: "at+jwt"} // wrong typ for ID token
	var errs []error
	errs = hdr.IsAllowedTyp(errs, []string{"JWT"})
	if len(errs) == 0 {
		t.Fatal("expected IsAllowedTyp to produce an error")
	}

	// Thread header errors into Validate - claims are valid, so only header error remains.
	err := v.Validate(errs, claims, now)
	if err == nil {
		t.Fatal("expected error from threaded header validation")
	}
	if !strings.Contains(err.Error(), "typ") {
		t.Errorf("expected typ error in output: %v", err)
	}
}
