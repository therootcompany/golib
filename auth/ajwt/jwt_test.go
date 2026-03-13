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
	"fmt"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/ajwt"
)

// AppClaims embeds StandardClaims and adds application-specific fields.
//
// Unlike embeddedjwt and bestjwt, AppClaims does NOT implement a Validate
// interface — there is none. Validation is explicit: call
// ValidateStandardClaims or ValidateParams.Validate at the call site.
type AppClaims struct {
	ajwt.StandardClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// validateAppClaims is a plain function — not a method satisfying an interface.
// Custom validation logic lives here, calling ValidateStandardClaims directly.
func validateAppClaims(c AppClaims, params ajwt.ValidateParams, now time.Time) ([]string, error) {
	errs, _ := ajwt.ValidateStandardClaims(c.StandardClaims, params, now)
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

// goodParams configures the validator. Iss is omitted because Issuer.Verify
// already enforces the iss claim — no need to check it twice.
func goodParams() ajwt.ValidateParams {
	return ajwt.ValidateParams{
		IgnoreIss:    true, // Issuer.Verify handles iss
		Sub:          "user123",
		Aud:          "myapp",
		Jti:          "abc123",
		Nonce:        "nonce1",
		Azp:          "myapp",
		RequiredAmrs: []string{"pwd"},
	}
}

func goodIssuer(pub ajwt.PublicJWK) *ajwt.Issuer {
	iss := ajwt.NewIssuer("https://example.com")
	iss.Params = goodParams()
	iss.SetKeys([]ajwt.PublicJWK{pub})
	return iss
}

// TestRoundTrip is the primary happy path using ES256.
// It demonstrates the full Issuer-based flow:
//
//	Decode → Issuer.Verify → UnmarshalClaims → Params.Validate
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

	jws2, err := ajwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err = iss.Verify(jws2); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	var decoded AppClaims
	if err = jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatal(err)
	}
	if errs, err := iss.Params.Validate(decoded.StandardClaims, time.Now()); err != nil {
		t.Fatalf("validation failed: %v", errs)
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

	jws2, err := ajwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err = iss.Verify(jws2); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	var decoded AppClaims
	if err = jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatal(err)
	}
	if errs, err := iss.Params.Validate(decoded.StandardClaims, time.Now()); err != nil {
		t.Fatalf("validation failed: %v", errs)
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

	jws2, err := ajwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err = iss.Verify(jws2); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	var decoded AppClaims
	if err = jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatal(err)
	}
	if errs, err := iss.Params.Validate(decoded.StandardClaims, time.Now()); err != nil {
		t.Fatalf("validation failed: %v", errs)
	}
}

// TestCustomValidation demonstrates custom claim validation without any interface.
// The caller owns the validation logic and calls ValidateStandardClaims directly.
func TestCustomValidation(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Token with empty Email — our custom validator should reject it.
	claims := goodClaims()
	claims.Email = ""
	jws, _ := ajwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &privKey.PublicKey, KID: "k"})
	jws2, _ := ajwt.Decode(token)
	_ = iss.Verify(jws2)
	var decoded AppClaims
	_ = jws2.UnmarshalClaims(&decoded)

	errs, err := validateAppClaims(decoded, goodParams(), time.Now())
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

// TestIssuerWrongKey confirms that a different key's public key is rejected.
func TestIssuerWrongKey(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := ajwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(signingKey)
	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &wrongKey.PublicKey, KID: "k"})
	jws2, _ := ajwt.Decode(token)

	if err := iss.Verify(jws2); err == nil {
		t.Fatal("expected Verify to fail with wrong key")
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
	jws2, _ := ajwt.Decode(token)

	if err := iss.Verify(jws2); err == nil {
		t.Fatal("expected Verify to fail for unknown kid")
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
	jws2, _ := ajwt.Decode(token)

	if err := iss.Verify(jws2); err == nil {
		t.Fatal("expected Verify to fail: iss mismatch")
	}
}

// TestVerifyTamperedAlg confirms that a tampered alg header is rejected.
func TestVerifyTamperedAlg(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := ajwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	iss := goodIssuer(ajwt.PublicJWK{Key: &privKey.PublicKey, KID: "k"})
	jws2, _ := ajwt.Decode(token)
	jws2.Header.Alg = "none" // tamper

	if err := iss.Verify(jws2); err == nil {
		t.Fatal("expected Verify to fail for tampered alg")
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
