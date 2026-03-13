// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package ajwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/ajwt"
)

// AppClaims embeds StandardClaims and adds application-specific fields.
//
// Because StandardClaims is embedded, AppClaims satisfies StandardClaimsSource
// for free via Go's method promotion — no interface to implement.
type AppClaims struct {
	ajwt.StandardClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// validateAppClaims is a plain function — not a method satisfying an interface.
// It demonstrates the UnsafeVerify pattern: custom validation logic lives here,
// calling ValidateStandardClaims directly and adding app-specific checks.
func validateAppClaims(c AppClaims, v ajwt.Validator, now time.Time) ([]string, error) {
	errs, _ := ajwt.ValidateStandardClaims(c.StandardClaims, v, now)
	if c.Email == "" {
		errs = append(errs, "missing email claim")
	}
	if len(errs) > 0 {
		return errs, fmt.Errorf("has errors")
	}
	return nil, nil
}

func goodClaims() AppClaims {
	now := time.Now()
	return AppClaims{
		StandardClaims: ajwt.StandardClaims{
			Iss:      "https://example.com",
			Sub:      "user123",
			Aud:      "myapp",
			Exp:      now.Add(time.Hour).Unix(),
			Iat:      now.Unix(),
			AuthTime: now.Unix(),
			Amr:      []string{"pwd"},
			Jti:      "abc123",
			Azp:      "myapp",
			Nonce:    "nonce1",
		},
		Email: "user@example.com",
		Roles: []string{"admin"},
	}
}

// goodValidator configures the validator. IgnoreIss is true because
// Issuer.UnsafeVerify already enforces the iss claim — no need to check twice.
func goodValidator() *ajwt.Validator {
	return &ajwt.Validator{
		IgnoreIss:    true, // UnsafeVerify handles iss
		Sub:          "user123",
		Aud:          "myapp",
		Jti:          "abc123",
		Nonce:        "nonce1",
		Azp:          "myapp",
		RequiredAmrs: []string{"pwd"},
	}
}

func goodIssuer(pub ajwt.PublicJWK) *ajwt.Issuer {
	return ajwt.New("https://example.com", []ajwt.PublicJWK{pub}, goodValidator())
}

// TestRoundTrip is the primary happy path using ES256.
// It demonstrates the full VerifyAndValidate flow:
//
//	New → VerifyAndValidate → custom claim access
//
// No Claims interface, no Verified flag, no type assertions on jws.
func TestRoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := ajwt.NewJWSFromClaims(&claims, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(privKey); err != nil {
		t.Fatal(err)
	}
	if jws.Header.Alg != "ES256" {
		t.Fatalf("expected ES256, got %s", jws.Header.Alg)
	}

	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &privKey.PublicKey, KID: "key-1"})

	var decoded AppClaims
	jws2, errs, err := iss.VerifyAndValidate(token, &decoded, time.Now())
	if err != nil {
		t.Fatalf("VerifyAndValidate failed: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("claim validation failed: %v", errs)
	}
	if jws2.Header.Alg != "ES256" {
		t.Errorf("expected ES256 alg in jws, got %s", jws2.Header.Alg)
	}
	// Direct field access — no type assertion needed, no jws.Claims interface.
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

	claims := goodClaims()
	jws, err := ajwt.NewJWSFromClaims(&claims, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(privKey); err != nil {
		t.Fatal(err)
	}
	if jws.Header.Alg != "RS256" {
		t.Fatalf("expected RS256, got %s", jws.Header.Alg)
	}

	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &privKey.PublicKey, KID: "key-1"})

	var decoded AppClaims
	_, errs, err := iss.VerifyAndValidate(token, &decoded, time.Now())
	if err != nil {
		t.Fatalf("VerifyAndValidate failed: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("claim validation failed: %v", errs)
	}
}

// TestRoundTripEdDSA exercises Ed25519 / EdDSA (RFC 8037).
func TestRoundTripEdDSA(t *testing.T) {
	pubKeyBytes, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := ajwt.NewJWSFromClaims(&claims, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(privKey); err != nil {
		t.Fatal(err)
	}
	if jws.Header.Alg != "EdDSA" {
		t.Fatalf("expected EdDSA, got %s", jws.Header.Alg)
	}

	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: pubKeyBytes, KID: "key-1"})

	var decoded AppClaims
	_, errs, err := iss.VerifyAndValidate(token, &decoded, time.Now())
	if err != nil {
		t.Fatalf("VerifyAndValidate failed: %v", err)
	}
	if len(errs) > 0 {
		t.Fatalf("claim validation failed: %v", errs)
	}
}

// TestUnsafeVerifyFlow demonstrates the UnsafeVerify + custom validation pattern.
// The caller owns the full validation pipeline.
func TestUnsafeVerifyFlow(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := ajwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	// Create issuer without validator — UnsafeVerify only.
	iss := ajwt.New("https://example.com", []ajwt.PublicJWK{{Key: &privKey.PublicKey, KID: "k"}}, nil)

	jws2, err := iss.UnsafeVerify(token)
	if err != nil {
		t.Fatalf("UnsafeVerify failed: %v", err)
	}

	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}

	errs, err := ajwt.ValidateStandardClaims(decoded.StandardClaims, *goodValidator(), time.Now())
	if err != nil {
		t.Fatalf("ValidateStandardClaims failed: %v — errs: %v", err, errs)
	}
}

// TestCustomValidation demonstrates that ValidateStandardClaims is called
// explicitly and custom fields are validated without any Claims interface.
func TestCustomValidation(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Token with empty Email — our custom validator should reject it.
	claims := goodClaims()
	claims.Email = ""
	jws, _ := ajwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &privKey.PublicKey, KID: "k"})
	jws2, err := iss.UnsafeVerify(token)
	if err != nil {
		t.Fatalf("UnsafeVerify failed unexpectedly: %v", err)
	}

	var decoded AppClaims
	_ = jws2.UnmarshalClaims(&decoded)

	errs, err := validateAppClaims(decoded, *goodValidator(), time.Now())
	if err == nil {
		t.Fatal("expected validation to fail: email is empty")
	}
	found := false
	for _, e := range errs {
		if e == "missing email claim" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'missing email claim' in errors: %v", errs)
	}
}

// TestVerifyAndValidateNilValidator confirms that VerifyAndValidate fails loudly
// when no Validator was provided at construction time.
func TestVerifyAndValidateNilValidator(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := goodClaims()
	jws, _ := ajwt.NewJWSFromClaims(&c, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	iss := ajwt.New("https://example.com", []ajwt.PublicJWK{{Key: &privKey.PublicKey, KID: "k"}}, nil)

	var claims AppClaims
	if _, _, err := iss.VerifyAndValidate(token, &claims, time.Now()); err == nil {
		t.Fatal("expected VerifyAndValidate to error with nil validator")
	}
}

// TestIssuerWrongKey confirms that a different key's public key is rejected.
func TestIssuerWrongKey(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := ajwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(signingKey)
	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &wrongKey.PublicKey, KID: "k"})

	if _, err := iss.UnsafeVerify(token); err == nil {
		t.Fatal("expected UnsafeVerify to fail with wrong key")
	}
}

// TestIssuerUnknownKid confirms that an unknown kid is rejected.
func TestIssuerUnknownKid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := ajwt.NewJWSFromClaims(&claims, "unknown-kid")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &privKey.PublicKey, KID: "known-kid"})

	if _, err := iss.UnsafeVerify(token); err == nil {
		t.Fatal("expected UnsafeVerify to fail for unknown kid")
	}
}

// TestIssuerIssMismatch confirms that a token with a mismatched iss is rejected
// even if the signature is valid.
func TestIssuerIssMismatch(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	claims.Iss = "https://evil.example.com" // not the issuer URL
	jws, _ := ajwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	// Issuer expects "https://example.com" but token says "https://evil.example.com"
	iss := goodIssuer(ajwt.PublicJWK{Key: &privKey.PublicKey, KID: "k"})

	if _, err := iss.UnsafeVerify(token); err == nil {
		t.Fatal("expected UnsafeVerify to fail: iss mismatch")
	}
}

// TestVerifyTamperedAlg confirms that a tampered alg header ("none") is rejected.
// The token is reconstructed with a replaced protected header; the original
// ES256 signature is kept, making the signing input mismatch detectable.
func TestVerifyTamperedAlg(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := ajwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &privKey.PublicKey, KID: "k"})

	// Replace the protected header with one that has alg:"none".
	// The original ES256 signature stays — the signing input will mismatch.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k","typ":"JWT"}`))
	parts := strings.SplitN(token, ".", 3)
	tamperedToken := noneHeader + "." + parts[1] + "." + parts[2]

	if _, err := iss.UnsafeVerify(tamperedToken); err == nil {
		t.Fatal("expected UnsafeVerify to fail for tampered alg")
	}
}

// TestPublicJWKAccessors confirms the ECDSA, RSA, and EdDSA typed accessor methods.
func TestPublicJWKAccessors(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	ecJWK := ajwt.PublicJWK{Key: &ecKey.PublicKey, KID: "ec-1"}
	rsaJWK := ajwt.PublicJWK{Key: &rsaKey.PublicKey, KID: "rsa-1"}
	edJWK := ajwt.PublicJWK{Key: edPub, KID: "ed-1"}

	if k, ok := ecJWK.ECDSA(); !ok || k == nil {
		t.Error("expected ECDSA() to succeed for EC key")
	}
	if _, ok := ecJWK.RSA(); ok {
		t.Error("expected RSA() to fail for EC key")
	}
	if _, ok := ecJWK.EdDSA(); ok {
		t.Error("expected EdDSA() to fail for EC key")
	}

	if k, ok := rsaJWK.RSA(); !ok || k == nil {
		t.Error("expected RSA() to succeed for RSA key")
	}
	if _, ok := rsaJWK.ECDSA(); ok {
		t.Error("expected ECDSA() to fail for RSA key")
	}
	if _, ok := rsaJWK.EdDSA(); ok {
		t.Error("expected EdDSA() to fail for RSA key")
	}

	if k, ok := edJWK.EdDSA(); !ok || k == nil {
		t.Error("expected EdDSA() to succeed for Ed25519 key")
	}
	if _, ok := edJWK.ECDSA(); ok {
		t.Error("expected ECDSA() to fail for Ed25519 key")
	}
	if _, ok := edJWK.RSA(); ok {
		t.Error("expected RSA() to fail for Ed25519 key")
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

	keys, err := ajwt.UnmarshalPublicJWKs(jwksJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	var ecCount, rsaCount int
	for _, k := range keys {
		if _, ok := k.ECDSA(); ok {
			ecCount++
			if k.KID != "ec-256" {
				t.Errorf("unexpected EC kid: %s", k.KID)
			}
		}
		if _, ok := k.RSA(); ok {
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
		jwk  ajwt.PublicJWK
	}{
		{"EC P-256", ajwt.PublicJWK{Key: &ecKey.PublicKey}},
		{"RSA 2048", ajwt.PublicJWK{Key: &rsaKey.PublicKey}},
		{"Ed25519", ajwt.PublicJWK{Key: edPub}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			thumb, err := tt.jwk.Thumbprint()
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
			// Same key → same thumbprint
			thumb2, _ := tt.jwk.Thumbprint()
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

	keys, err := ajwt.UnmarshalPublicJWKs(jwksJSON)
	if err != nil {
		t.Fatal(err)
	}
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
