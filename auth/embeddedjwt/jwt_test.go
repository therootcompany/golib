// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package embeddedjwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/embeddedjwt"
)

// AppClaims embeds StandardClaims and gains Validate via promotion.
// No Validate override — demonstrates zero-boilerplate satisfaction of Claims.
type AppClaims struct {
	embeddedjwt.StandardClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// StrictAppClaims overrides Validate to also require a non-empty Email,
// demonstrating how to layer application-specific checks on top of the
// promoted standard validation.
type StrictAppClaims struct {
	embeddedjwt.StandardClaims
	Email string `json:"email"`
}

func (c StrictAppClaims) Validate(params embeddedjwt.ValidateParams) ([]string, error) {
	errs, _ := embeddedjwt.ValidateStandardClaims(c.StandardClaims, params)
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
		StandardClaims: embeddedjwt.StandardClaims{
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

func goodParams() embeddedjwt.ValidateParams {
	return embeddedjwt.ValidateParams{
		Iss:          "https://example.com",
		Sub:          "user123",
		Aud:          "myapp",
		Jti:          "abc123",
		Nonce:        "nonce1",
		Azp:          "myapp",
		RequiredAmrs: []string{"pwd"},
	}
}

// TestRoundTrip is the primary happy path: sign, encode, decode, verify,
// validate — and confirm that custom fields are accessible without a type
// assertion via the local &claims pointer.
func TestRoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := embeddedjwt.NewJWSFromClaims(&claims, "key-1")
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

	var decoded AppClaims
	jws2, err := embeddedjwt.Decode(token, &decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !jws2.UnsafeVerify(&privKey.PublicKey) {
		t.Fatal("signature verification failed")
	}
	if errs, err := jws2.Validate(goodParams()); err != nil {
		t.Fatalf("validation failed: %v", errs)
	}
	// Access custom field directly — no type assertion on jws2.Claims needed.
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
	jws, err := embeddedjwt.NewJWSFromClaims(&claims, "key-1")
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

	var decoded AppClaims
	jws2, err := embeddedjwt.Decode(token, &decoded)
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

// TestPromotedValidate confirms that AppClaims satisfies Claims via the
// promoted Validate from embedded StandardClaims, with no method written.
func TestPromotedValidate(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := embeddedjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	var decoded AppClaims
	jws2, _ := embeddedjwt.Decode(token, &decoded)
	jws2.UnsafeVerify(&privKey.PublicKey)

	if errs, err := jws2.Validate(goodParams()); err != nil {
		t.Fatalf("promoted Validate failed unexpectedly: %v", errs)
	}
}

// TestOverriddenValidate confirms that StrictAppClaims.Validate is called
// (not the promoted one) and that the missing Email is caught.
func TestOverriddenValidate(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	now := time.Now()
	claims := StrictAppClaims{
		StandardClaims: embeddedjwt.StandardClaims{
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
		Email: "", // intentionally empty
	}

	jws, _ := embeddedjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	var decoded StrictAppClaims
	jws2, _ := embeddedjwt.Decode(token, &decoded)
	jws2.UnsafeVerify(&privKey.PublicKey)

	errs, err := jws2.Validate(goodParams())
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

// TestUnsafeVerifyWrongKey confirms that a different key's public key does
// not verify the signature.
func TestUnsafeVerifyWrongKey(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := embeddedjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(signingKey)
	token := jws.Encode()

	var decoded AppClaims
	jws2, _ := embeddedjwt.Decode(token, &decoded)

	if jws2.UnsafeVerify(&wrongKey.PublicKey) {
		t.Fatal("expected verification to fail with wrong key")
	}
}

// TestVerifyWrongKeyType confirms that an RSA key is rejected for an ES256 token.
func TestVerifyWrongKeyType(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := goodClaims()
	jws, _ := embeddedjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(ecKey)
	token := jws.Encode()

	var decoded AppClaims
	jws2, _ := embeddedjwt.Decode(token, &decoded)

	if jws2.UnsafeVerify(&rsaKey.PublicKey) {
		t.Fatal("expected verification to fail: RSA key for ES256 token")
	}
}

// TestVerifyUnknownAlg confirms that a tampered alg header is rejected.
func TestVerifyUnknownAlg(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := embeddedjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	var decoded AppClaims
	jws2, _ := embeddedjwt.Decode(token, &decoded)
	jws2.Header.Alg = "none"

	if jws2.UnsafeVerify(&privKey.PublicKey) {
		t.Fatal("expected verification to fail for unknown alg")
	}
}

// TestVerifyWithJWKSKey confirms that PublicJWK.Key can be passed directly to
// UnsafeVerify without a type assertion.
func TestVerifyWithJWKSKey(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwksKey := embeddedjwt.PublicJWK{Key: &privKey.PublicKey, KID: "k1"}

	claims := goodClaims()
	jws, _ := embeddedjwt.NewJWSFromClaims(&claims, "k1")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	var decoded AppClaims
	jws2, _ := embeddedjwt.Decode(token, &decoded)

	if !jws2.UnsafeVerify(jwksKey.Key) {
		t.Fatal("verification via PublicJWK.Key failed")
	}
}

// TestPublicJWKAccessors confirms the ECDSA() and RSA() typed accessor methods.
func TestPublicJWKAccessors(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	ecJWK := embeddedjwt.PublicJWK{Key: &ecKey.PublicKey, KID: "ec-1"}
	rsaJWK := embeddedjwt.PublicJWK{Key: &rsaKey.PublicKey, KID: "rsa-1"}

	if k, ok := ecJWK.ECDSA(); !ok || k == nil {
		t.Error("expected ECDSA() to succeed for EC key")
	}
	if _, ok := ecJWK.RSA(); ok {
		t.Error("expected RSA() to fail for EC key")
	}

	if k, ok := rsaJWK.RSA(); !ok || k == nil {
		t.Error("expected RSA() to succeed for RSA key")
	}
	if _, ok := rsaJWK.ECDSA(); ok {
		t.Error("expected ECDSA() to fail for RSA key")
	}
}

// TestDecodePublicJWKJSON verifies JWKS JSON parsing and the typed accessors
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

	keys, err := embeddedjwt.UnmarshalPublicJWKs(jwksJSON)
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
