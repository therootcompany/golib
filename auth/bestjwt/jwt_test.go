// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package bestjwt_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/bestjwt"
)

// AppClaims is an example custom claims type.
// Embedding StandardClaims promotes Validate — no boilerplate needed.
type AppClaims struct {
	bestjwt.StandardClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// StrictAppClaims overrides Validate to also require a non-empty Email.
// This demonstrates how to add application-specific validation on top of
// the standard OIDC checks.
type StrictAppClaims struct {
	bestjwt.StandardClaims
	Email string `json:"email"`
}

func (c StrictAppClaims) Validate(params bestjwt.ValidateParams) ([]string, error) {
	errs, _ := bestjwt.ValidateStandardClaims(c.StandardClaims, params)
	if c.Email == "" {
		errs = append(errs, "missing email claim")
	}
	if len(errs) > 0 {
		return errs, fmt.Errorf("has errors")
	}
	return nil, nil
}

// goodClaims returns a valid AppClaims with all standard fields populated.
func goodClaims() AppClaims {
	now := time.Now()
	return AppClaims{
		StandardClaims: bestjwt.StandardClaims{
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

// goodParams returns ValidateParams matching the claims from goodClaims.
func goodParams() bestjwt.ValidateParams {
	return bestjwt.ValidateParams{
		Iss:          "https://example.com",
		Sub:          "user123",
		Aud:          "myapp",
		Jti:          "abc123",
		Nonce:        "nonce1",
		Azp:          "myapp",
		RequiredAmrs: []string{"pwd"},
	}
}

// --- Round-trip tests (sign → encode → decode → verify → validate) ---

// TestRoundTripES256 exercises the most common path: ECDSA P-256 / ES256.
// Demonstrates the Decode(&claims) ergonomic — no generics at the call site,
// no type assertion needed to access Email after decoding.
func TestRoundTripES256(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := bestjwt.NewJWSFromClaims(&claims, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(privKey); err != nil {
		t.Fatal(err)
	}
	if jws.Header.Alg != "ES256" {
		t.Fatalf("expected ES256, got %s", jws.Header.Alg)
	}
	if len(jws.Signature) != 64 { // P-256: 32 bytes each for r and s
		t.Fatalf("expected 64-byte signature, got %d", len(jws.Signature))
	}

	token := jws.Encode()

	var decoded AppClaims
	jws2, err := bestjwt.Decode(token, &decoded)
	if err != nil {
		t.Fatal(err)
	}
	if !jws2.UnsafeVerify(&privKey.PublicKey) {
		t.Fatal("signature verification failed")
	}
	if errs, err := jws2.Validate(goodParams()); err != nil {
		t.Fatalf("validation failed: %v", errs)
	}
	// Direct field access via the local variable — no type assertion.
	if decoded.Email != claims.Email {
		t.Errorf("email: got %s, want %s", decoded.Email, claims.Email)
	}
}

// TestRoundTripES384 exercises ECDSA P-384 / ES384, verifying that the
// algorithm is inferred from the key's curve and that the 96-byte r||s
// signature format is produced and verified correctly.
func TestRoundTripES384(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := bestjwt.NewJWSFromClaims(&claims, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(privKey); err != nil {
		t.Fatal(err)
	}
	if jws.Header.Alg != "ES384" {
		t.Fatalf("expected ES384, got %s", jws.Header.Alg)
	}
	if len(jws.Signature) != 96 { // P-384: 48 bytes each for r and s
		t.Fatalf("expected 96-byte signature, got %d", len(jws.Signature))
	}

	token := jws.Encode()

	var decoded AppClaims
	jws2, err := bestjwt.Decode(token, &decoded)
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

// TestRoundTripES512 exercises ECDSA P-521 / ES512 and the 132-byte signature.
func TestRoundTripES512(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := bestjwt.NewJWSFromClaims(&claims, "key-1")
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(privKey); err != nil {
		t.Fatal(err)
	}
	if jws.Header.Alg != "ES512" {
		t.Fatalf("expected ES512, got %s", jws.Header.Alg)
	}
	if len(jws.Signature) != 132 { // P-521: 66 bytes each for r and s
		t.Fatalf("expected 132-byte signature, got %d", len(jws.Signature))
	}

	token := jws.Encode()

	var decoded AppClaims
	jws2, err := bestjwt.Decode(token, &decoded)
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

// TestRoundTripRS256 exercises RSA PKCS#1 v1.5 / RS256.
func TestRoundTripRS256(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	jws, err := bestjwt.NewJWSFromClaims(&claims, "key-1")
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
	jws2, err := bestjwt.Decode(token, &decoded)
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

// --- Security / negative tests ---

// TestVerifyWrongKeyType verifies that an RSA public key is rejected when
// verifying a token signed with ECDSA (alg = ES256).
func TestVerifyWrongKeyType(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	claims := goodClaims()
	jws, _ := bestjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(ecKey) // alg = "ES256"

	token := jws.Encode()
	var decoded AppClaims
	jws2, _ := bestjwt.Decode(token, &decoded)

	if jws2.UnsafeVerify(&rsaKey.PublicKey) {
		t.Fatal("expected verification to fail: RSA key for ES256 token")
	}
}

// TestVerifyAlgCurveMismatch verifies that a P-256 key is rejected when
// verifying a token whose header claims ES384 (signed with P-384).
// Without the curve/alg consistency check this would silently return false
// from ecdsa.Verify, but the explicit check makes the rejection reason clear.
func TestVerifyAlgCurveMismatch(t *testing.T) {
	p384Key, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	p256Key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := bestjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(p384Key) // alg = "ES384"

	token := jws.Encode()
	var decoded AppClaims
	jws2, _ := bestjwt.Decode(token, &decoded)

	// P-256 key must be rejected for an ES384 token.
	if jws2.UnsafeVerify(&p256Key.PublicKey) {
		t.Fatal("expected verification to fail: P-256 key for ES384 token")
	}
}

// TestVerifyUnknownAlg verifies that a tampered alg header is rejected.
func TestVerifyUnknownAlg(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := bestjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)

	token := jws.Encode()
	var decoded AppClaims
	jws2, _ := bestjwt.Decode(token, &decoded)

	// Tamper: overwrite alg in the decoded header.
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
	jws, _ := bestjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)

	token := jws.Encode()
	var decoded AppClaims
	jws2, _ := bestjwt.Decode(token, &decoded)

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

// --- Embedded vs overridden Validate ---

// TestPromotedValidate confirms that AppClaims (which only embeds
// StandardClaims) gets the standard OIDC validation for free via promotion,
// without writing any Validate method.
func TestPromotedValidate(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	jws, _ := bestjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	var decoded AppClaims
	jws2, _ := bestjwt.Decode(token, &decoded)
	jws2.UnsafeVerify(&privKey.PublicKey)

	if errs, err := jws2.Validate(goodParams()); err != nil {
		t.Fatalf("promoted Validate failed unexpectedly: %v", errs)
	}
}

// TestOverriddenValidate confirms that a StrictAppClaims with an empty Email
// fails validation via its overridden Validate method.
func TestOverriddenValidate(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	now := time.Now()
	claims := StrictAppClaims{
		StandardClaims: bestjwt.StandardClaims{
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
		Email: "", // intentionally empty to trigger the override
	}

	jws, _ := bestjwt.NewJWSFromClaims(&claims, "k")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	var decoded StrictAppClaims
	jws2, _ := bestjwt.Decode(token, &decoded)
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

// --- JWKS / key management ---

// TestTypedKeys verifies that TypedKeys correctly filters a mixed
// []PublicJWK[Key] into typed slices without type assertions at use sites.
func TestTypedKeys(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)

	allKeys := []bestjwt.PublicJWK[bestjwt.Key]{
		{Key: &ecKey.PublicKey, KID: "ec-1", Use: "sig"},
		{Key: &rsaKey.PublicKey, KID: "rsa-1", Use: "sig"},
	}

	ecKeys := bestjwt.TypedKeys[*ecdsa.PublicKey](allKeys)
	if len(ecKeys) != 1 || ecKeys[0].KID != "ec-1" {
		t.Errorf("unexpected EC keys: %+v", ecKeys)
	}
	// Typed access — no assertion needed.
	_ = ecKeys[0].Key.Curve

	rsaKeys := bestjwt.TypedKeys[*rsa.PublicKey](allKeys)
	if len(rsaKeys) != 1 || rsaKeys[0].KID != "rsa-1" {
		t.Errorf("unexpected RSA keys: %+v", rsaKeys)
	}
}

// TestVerifyWithJWKSKey verifies that PublicJWK.Key can be passed directly to
// UnsafeVerify without a type assertion when using a typed PublicJWK[Key].
func TestVerifyWithJWKSKey(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	jwksKey := bestjwt.PublicJWK[bestjwt.Key]{Key: &privKey.PublicKey, KID: "k1"}

	claims := goodClaims()
	jws, _ := bestjwt.NewJWSFromClaims(&claims, "k1")
	_, _ = jws.Sign(privKey)
	token := jws.Encode()

	var decoded AppClaims
	jws2, _ := bestjwt.Decode(token, &decoded)

	// Pass PublicJWK.Key directly — Key interface satisfies the Key constraint.
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

	keys, err := bestjwt.UnmarshalPublicJWKs(jwksJSON)
	if err != nil {
		t.Fatal(err)
	}
	if len(keys) != 2 {
		t.Fatalf("expected 2 keys, got %d", len(keys))
	}

	ecKeys := bestjwt.TypedKeys[*ecdsa.PublicKey](keys)
	if len(ecKeys) != 1 || ecKeys[0].KID != "ec-256" {
		t.Errorf("EC key mismatch: %+v", ecKeys)
	}

	rsaKeys := bestjwt.TypedKeys[*rsa.PublicKey](keys)
	if len(rsaKeys) != 1 || rsaKeys[0].KID != "rsa-2048" {
		t.Errorf("RSA key mismatch: %+v", rsaKeys)
	}
}
