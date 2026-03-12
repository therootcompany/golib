// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package genericjwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/genericjwt"
)

// AppClaims is an example custom claims type that satisfies [genericjwt.Validatable]
// by explicitly delegating to [genericjwt.ValidateStandardClaims].
//
// Unlike embeddedjwt, there is no promoted Validate here — genericjwt's
// StandardClaims has no Validate method, so the application type always owns
// the implementation. This keeps the generics constraint explicit.
type AppClaims struct {
	genericjwt.StandardClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

func (c AppClaims) Validate(params genericjwt.ValidateParams) ([]string, error) {
	return genericjwt.ValidateStandardClaims(c.StandardClaims, params)
}

// StrictAppClaims adds an application-specific check (non-empty Email) on top
// of the standard OIDC validation.
type StrictAppClaims struct {
	genericjwt.StandardClaims
	Email string `json:"email"`
}

func (c StrictAppClaims) Validate(params genericjwt.ValidateParams) ([]string, error) {
	errs, _ := genericjwt.ValidateStandardClaims(c.StandardClaims, params)
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
		StandardClaims: genericjwt.StandardClaims{
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

func goodParams() genericjwt.ValidateParams {
	return genericjwt.ValidateParams{
		Iss:          "https://example.com",
		Sub:          "user123",
		Aud:          "myapp",
		Jti:          "abc123",
		Nonce:        "nonce1",
		Azp:          "myapp",
		RequiredAmrs: []string{"pwd"},
	}
}

// TestRoundTrip is the primary happy path demonstrating the core genericjwt
// ergonomic: Decode[AppClaims] places the type parameter at the call site and
// returns a JWS[AppClaims] whose Claims field is directly typed — no interface,
// no type assertion ever needed.
func TestRoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := genericjwt.NewJWSFromClaims(claims, "key-1")
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

	// Type parameter at the call site — no pre-allocated claims pointer needed.
	jws2, err := genericjwt.Decode[AppClaims](token)
	if err != nil {
		t.Fatal(err)
	}
	if !jws2.UnsafeVerify(&privKey.PublicKey) {
		t.Fatal("signature verification failed")
	}
	if errs, err := jws2.Validate(goodParams()); err != nil {
		t.Fatalf("validation failed: %v", errs)
	}
	// Direct field access on jws2.Claims — zero type assertions.
	if jws2.Claims.Email != claims.Email {
		t.Errorf("email: got %s, want %s", jws2.Claims.Email, claims.Email)
	}
}

// TestRoundTripRS256 exercises RSA PKCS#1 v1.5 / RS256.
func TestRoundTripRS256(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := genericjwt.NewJWSFromClaims(claims, "key-1")
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

	jws2, err := genericjwt.Decode[AppClaims](token)
	if err != nil {
		t.Fatal(err)
	}
	if !jws2.UnsafeVerify(&privKey.PublicKey) {
		t.Fatal("signature verification failed")
	}
	if errs, err := jws2.Validate(goodParams()); err != nil {
		t.Fatalf("validation failed: %v", errs)
	}
}

// TestUnsafeVerifyWrongKey confirms that a different key's public key does
// not verify the signature.
func TestUnsafeVerifyWrongKey(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := genericjwt.NewJWSFromClaims(claims, "k")
	_, _ = jws.Sign(signingKey)
	token := jws.Encode()

	jws2, _ := genericjwt.Decode[AppClaims](token)

	if jws2.UnsafeVerify(&wrongKey.PublicKey) {
		t.Fatal("expected verification to fail with wrong key")
	}
}

// TestVerifyWrongKeyType confirms that an RSA key is rejected for an ES256 token.
func TestVerifyWrongKeyType(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := goodClaims()
	jws, _ := genericjwt.NewJWSFromClaims(claims, "k")
	_, _ = jws.Sign(ecKey)
	token := jws.Encode()

	jws2, _ := genericjwt.Decode[AppClaims](token)

	if jws2.UnsafeVerify(&rsaKey.PublicKey) {
		t.Fatal("expected verification to fail: RSA key for ES256 token")
	}
}

// TestVerifyUnknownAlg confirms that a tampered alg header is rejected.
func TestVerifyUnknownAlg(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := genericjwt.NewJWSFromClaims(claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	jws2, _ := genericjwt.Decode[AppClaims](token)
	jws2.Header.Alg = "none"

	if jws2.UnsafeVerify(&privKey.PublicKey) {
		t.Fatal("expected verification to fail for unknown alg")
	}
}

// TestValidateMissingSignatureCheck verifies that Validate fails when
// UnsafeVerify was never called (Verified is false).
func TestValidateMissingSignatureCheck(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := genericjwt.NewJWSFromClaims(claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	jws2, _ := genericjwt.Decode[AppClaims](token)

	// Deliberately skip UnsafeVerify.
	errs, err := jws2.Validate(goodParams())
	if err == nil {
		t.Fatal("expected validation to fail: signature was not checked")
	}
	found := false
	for _, e := range errs {
		if e == "signature was not checked" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected 'signature was not checked' in errors: %v", errs)
	}
}

// TestVerifyWithJWKSKey verifies that PublicJWK[Key].Key can be passed
// directly to UnsafeVerify — the Key interface satisfies UnsafeVerify's
// parameter constraint without a type assertion.
func TestVerifyWithJWKSKey(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwksKey := genericjwt.PublicJWK[genericjwt.Key]{Key: &privKey.PublicKey, KID: "k1"}

	claims := goodClaims()
	jws, _ := genericjwt.NewJWSFromClaims(claims, "k1")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	jws2, _ := genericjwt.Decode[AppClaims](token)

	if !jws2.UnsafeVerify(jwksKey.Key) {
		t.Fatal("verification via PublicJWK.Key failed")
	}
}

// TestDecodePublicJWKJSON verifies JWKS JSON parsing and TypedKeys filtering
// with real base64url-encoded key material from RFC 7517 / OIDC examples.
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

	keys, err := genericjwt.UnmarshalPublicJWKs(jwksJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	ecKeys := genericjwt.TypedKeys[*ecdsa.PublicKey](keys)
	if len(ecKeys) != 1 || ecKeys[0].KID != "ec-256" {
		t.Errorf("EC key mismatch: %+v", ecKeys)
	}

	rsaKeys := genericjwt.TypedKeys[*rsa.PublicKey](keys)
	if len(rsaKeys) != 1 || rsaKeys[0].KID != "rsa-2048" {
		t.Errorf("RSA key mismatch: %+v", rsaKeys)
	}
}
