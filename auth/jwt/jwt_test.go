// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
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
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// AppClaims embeds StandardClaims and adds application-specific fields.
//
// Because StandardClaims is embedded, AppClaims satisfies Claims
// for free via Go's method promotion — no interface to implement.
type AppClaims struct {
	jwt.StandardClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// validateAppClaims is a plain function — not a method satisfying an interface.
// It demonstrates the Decode+Verify pattern: custom validation logic lives here,
// calling Validator.Validate and adding app-specific checks.
func validateAppClaims(c AppClaims, v *jwt.ValidatorStrict, now time.Time) ([]string, error) {
	errs, _ := v.Validate(&c, now)
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
		StandardClaims: jwt.StandardClaims{
			Iss:      "https://example.com",
			Sub:      "user123",
			Aud:      jwt.Audience{"myapp"},
			Exp:      now.Add(time.Hour).Unix(),
			Iat:      now.Unix(),
			AuthTime: now.Unix(),
			AMR:      []string{"pwd"},
			JTI:      "abc123",
			Azp:      "myapp",
			Nonce:    "nonce1",
		},
		Email: "user@example.com",
		Roles: []string{"admin"},
	}
}

// goodValidator configures the strict validator with iss set to "https://example.com".
// Iss checking is now the Validator's responsibility, not the Verifier's.
func goodValidator() *jwt.ValidatorStrict {
	return &jwt.ValidatorStrict{
		ValidatorCore: jwt.ValidatorCore{
			Iss:          []string{"https://example.com"},
			Aud:          []string{"myapp"},
			Azp:          []string{"myapp"},
			RequiredAMRs: []string{"pwd"},
		},
	}
}

func goodVerifier(pub jwk.PublicKey) *jwt.Verifier {
	return jwt.New([]jwk.PublicKey{pub})
}

// TestRoundTrip is the primary happy path using ES256.
// It demonstrates the full Verify → UnmarshalClaims → Validate flow.
func TestRoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	pk := &jwk.PrivateKey{KID: "key-1", Signer: privKey}
	jws, err := jwt.NewJWS(&claims)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(pk); err != nil {
		t.Fatal(err)
	}
	if jws.GetStandardHeader().Alg != "ES256" {
		t.Fatalf("expected ES256, got %s", jws.GetStandardHeader().Alg)
	}

	token := jws.Encode()

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if jws2.GetStandardHeader().Alg != "ES256" {
		t.Errorf("expected ES256 alg in jws, got %s", jws2.GetStandardHeader().Alg)
	}

	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	errs, _ := goodValidator().Validate(&decoded, time.Now())
	if len(errs) > 0 {
		t.Fatalf("claim validation failed: %v", errs)
	}
	// Direct field access — no type assertion needed.
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
	pk := &jwk.PrivateKey{KID: "key-1", Signer: privKey}
	jws, err := jwt.NewJWS(&claims)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(pk); err != nil {
		t.Fatal(err)
	}
	if jws.GetStandardHeader().Alg != "RS256" {
		t.Fatalf("expected RS256, got %s", jws.GetStandardHeader().Alg)
	}

	token := jws.Encode()

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	errs, _ := goodValidator().Validate(&decoded, time.Now())
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
	pk := &jwk.PrivateKey{KID: "key-1", Signer: privKey}
	jws, err := jwt.NewJWS(&claims)
	if err != nil {
		t.Fatal(err)
	}

	if _, err = jws.Sign(pk); err != nil {
		t.Fatal(err)
	}
	if jws.GetStandardHeader().Alg != "EdDSA" {
		t.Fatalf("expected EdDSA, got %s", jws.GetStandardHeader().Alg)
	}

	token := jws.Encode()

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: pubKeyBytes, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jws2.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	errs, _ := goodValidator().Validate(&decoded, time.Now())
	if len(errs) > 0 {
		t.Fatalf("claim validation failed: %v", errs)
	}
}

// TestDecodeVerifyFlow demonstrates the Decode + Verify + custom validation pattern.
// The caller owns the full validation pipeline.
func TestDecodeVerifyFlow(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	pk := &jwk.PrivateKey{KID: "k", Signer: privKey}
	jws, _ := jwt.NewJWS(&claims)
	_, _ = jws.Sign(pk)
	token := jws.Encode()

	iss := jwt.New([]jwk.PublicKey{{CryptoPublicKey: &privKey.PublicKey, KID: "k"}})

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

	errs, err := goodValidator().Validate(&decoded, time.Now())
	if err != nil {
		t.Fatalf("Validate failed: %v — errs: %v", err, errs)
	}
}

// TestDecodeReturnsParsedOnSigFailure verifies that Decode returns a non-nil
// *StandardJWS even when the token will later fail signature verification.
// Callers can inspect the header (kid, alg) for routing before calling Verify.
func TestDecodeReturnsParsedOnSigFailure(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	pk := &jwk.PrivateKey{KID: "k", Signer: signingKey}
	jws, _ := jwt.NewJWS(&claims)
	_, _ = jws.Sign(pk)
	token := jws.Encode()

	// Verifier has wrong public key — sig verification will fail.
	iss := jwt.New([]jwk.PublicKey{{CryptoPublicKey: &wrongKey.PublicKey, KID: "k"}})

	// Decode always succeeds for well-formed tokens.
	result, err := jwt.Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if result == nil {
		t.Fatal("Decode should return non-nil StandardJWS")
	}
	if result.GetStandardHeader().KID != "k" {
		t.Errorf("expected kid %q, got %q", "k", result.GetStandardHeader().KID)
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

	// Token with empty Email — our custom validator should reject it.
	claims := goodClaims()
	claims.Email = ""
	pk := &jwk.PrivateKey{KID: "k", Signer: privKey}
	jws, _ := jwt.NewJWS(&claims)
	_, _ = jws.Sign(pk)
	token := jws.Encode()

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "k"})
	jws2, err := jwt.Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if err := iss.Verify(jws2); err != nil {
		t.Fatalf("Verify failed unexpectedly: %v", err)
	}

	var decoded AppClaims
	_ = jws2.UnmarshalClaims(&decoded)

	errs, err := validateAppClaims(decoded, goodValidator(), time.Now())
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

// TestValidatorLax confirms that ValidatorLax always checks exp/iat, checks
// iss/aud/azp when configured, and skips sub/jti/auth_time/amr by default.
func TestValidatorLax(t *testing.T) {
	now := time.Now()

	// Minimal claims: only the fields ValidatorLax checks by default.
	minimal := AppClaims{
		StandardClaims: jwt.StandardClaims{
			Iss: "https://example.com",
			Aud: jwt.Audience{"myapp"},
			Exp: now.Add(time.Hour).Unix(),
			Iat: now.Unix(),
			// Sub, JTI, AuthTime, AMR, Azp intentionally absent
		},
		Email: "user@example.com",
	}

	lax := &jwt.ValidatorLax{
		ValidatorCore: jwt.ValidatorCore{
			Iss: []string{"https://example.com"},
			Aud: []string{"myapp"},
		},
	}

	errs, err := lax.Validate(&minimal, now)
	if err != nil {
		t.Fatalf("ValidatorLax rejected minimal valid claims: %v — errs: %v", err, errs)
	}

	// Expired token must still be rejected.
	expired := minimal
	expired.Exp = now.Add(-time.Hour).Unix()
	errs, err = lax.Validate(&expired, now)
	if err == nil {
		t.Fatal("ValidatorLax should reject expired token")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e, "expired") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected expiry error, got: %v", errs)
	}

	// Future iat must be rejected.
	futureIat := minimal
	futureIat.Iat = now.Add(time.Hour).Unix()
	errs, err = lax.Validate(&futureIat, now)
	if err == nil {
		t.Fatal("ValidatorLax should reject future-dated iat")
	}
	found = false
	for _, e := range errs {
		if strings.Contains(e, "iat") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected iat error, got: %v", errs)
	}

	// Opt-in CheckNonce: absent nonce must be caught.
	laxNonce := &jwt.ValidatorLax{
		ValidatorCore: jwt.ValidatorCore{
			Iss: []string{"https://example.com"},
			Aud: []string{"myapp"},
		},
		CheckNonce: true,
	}
	noNonce := minimal
	noNonce.Nonce = ""
	errs, err = laxNonce.Validate(&noNonce, now)
	if err == nil {
		t.Fatal("ValidatorLax should reject absent nonce when CheckNonce is set")
	}
	found = false
	for _, e := range errs {
		if strings.Contains(e, "nonce") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected nonce error, got: %v", errs)
	}
}

// TestVerifyWithoutValidation confirms that Verify + UnmarshalClaims succeeds
// independently of claim validation — the caller decides whether to validate.
func TestVerifyWithoutValidation(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	c := goodClaims()
	pk := &jwk.PrivateKey{KID: "k", Signer: privKey}
	jws, _ := jwt.NewJWS(&c)
	_, _ = jws.Sign(pk)
	token := jws.Encode()

	iss := jwt.New([]jwk.PublicKey{{CryptoPublicKey: &privKey.PublicKey, KID: "k"}})

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

	claims := goodClaims()
	pk := &jwk.PrivateKey{KID: "k", Signer: signingKey}
	jws, _ := jwt.NewJWS(&claims)
	_, _ = jws.Sign(pk)
	token := jws.Encode()

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &wrongKey.PublicKey, KID: "k"})

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); err == nil {
		t.Fatal("expected Verify to fail with wrong key")
	}
}

// TestVerifierUnknownKid confirms that an unknown kid is rejected.
func TestVerifierUnknownKid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	pk := &jwk.PrivateKey{KID: "unknown-kid", Signer: privKey}
	jws, _ := jwt.NewJWS(&claims)
	_, _ = jws.Sign(pk)
	token := jws.Encode()

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "known-kid"})

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); err == nil {
		t.Fatal("expected Verify to fail for unknown kid")
	}
}

// TestVerifierIssMismatch confirms that a token with a mismatched iss is caught
// by the Validator, not the Verifier. Signature verification succeeds; the iss
// mismatch appears as a soft validation error.
func TestVerifierIssMismatch(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	claims.Iss = "https://evil.example.com"
	pk := &jwk.PrivateKey{KID: "k", Signer: privKey}
	jws, _ := jwt.NewJWS(&claims)
	_, _ = jws.Sign(pk)
	token := jws.Encode()

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "k"})

	// Decode+Verify succeeds — iss is not checked at the Verifier level.
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
	errs, _ := goodValidator().Validate(&decoded, time.Now())
	if len(errs) == 0 {
		t.Fatal("expected validation errors for iss mismatch")
	}
	found := false
	for _, e := range errs {
		if strings.Contains(e, "iss") {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected iss error in validation errors: %v", errs)
	}
}

// TestVerifyTamperedAlg confirms that a tampered alg header ("none") is rejected.
// The token is reconstructed with a replaced protected header; the original
// ES256 signature is kept, making the signing input mismatch detectable.
func TestVerifyTamperedAlg(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	claims := goodClaims()
	pk := &jwk.PrivateKey{KID: "k", Signer: privKey}
	jws, _ := jwt.NewJWS(&claims)
	_, _ = jws.Sign(pk)
	token := jws.Encode()

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "k"})

	// Replace the protected header with one that has alg:"none".
	// The original ES256 signature stays — the signing input will mismatch.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k","typ":"JWT"}`))
	parts := strings.SplitN(token, ".", 3)
	tamperedToken := noneHeader + "." + parts[1] + "." + parts[2]

	parsed, err := jwt.Decode(tamperedToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); err == nil {
		t.Fatal("expected Verify to fail for tampered alg")
	}
}

// TestSignerRoundTrip verifies the Signer → Sign → Verifier → Verify → Validate flow.
func TestSignerRoundTrip(t *testing.T) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "k1", Signer: privKey}})
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
	errs, _ := goodValidator().Validate(&decoded, time.Now())
	if len(errs) > 0 {
		t.Fatalf("claim validation failed: %v", errs)
	}
	if decoded.Email != claims.Email {
		t.Errorf("email: got %s, want %s", decoded.Email, claims.Email)
	}
}

// TestSignerAutoKID verifies that KID is auto-computed from the key thumbprint
// when PrivateKey.KID is empty.
func TestSignerAutoKID(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := jwt.NewSigner([]jwk.PrivateKey{{Signer: privKey}})
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

	signer, err := jwt.NewSigner([]jwk.PrivateKey{
		{KID: "k1", Signer: key1},
		{KID: "k2", Signer: key2},
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
		if errs, _ := v.Validate(&decoded, time.Now()); len(errs) > 0 {
			t.Fatalf("Validate[%d] failed: %v", i, errs)
		}
	}
}

// TestJWKsRoundTrip verifies JWKS serialization and round-trip parsing.
func TestJWKsRoundTrip(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "k1", Signer: privKey}})
	if err != nil {
		t.Fatal(err)
	}

	jwksBytes, err := json.Marshal(signer)
	if err != nil {
		t.Fatal(err)
	}

	// Round-trip: parse the JWKS JSON and verify it produces a working Verifier.
	var jwks jwk.JWKs
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

	iss2 := jwt.New(keys)
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

// TestKeyAccessors confirms the ECDSA, RSA, and EdDSA typed accessor methods on jwk.Key.
func TestKeyAccessors(t *testing.T) {
	ecKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)

	ecJWK := jwk.PublicKey{CryptoPublicKey: &ecKey.PublicKey, KID: "ec-1"}
	rsaJWK := jwk.PublicKey{CryptoPublicKey: &rsaKey.PublicKey, KID: "rsa-1"}
	edJWK := jwk.PublicKey{CryptoPublicKey: edPub, KID: "ed-1"}

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

	var jwks jwk.JWKs
	if err := json.Unmarshal(jwksJSON, &jwks); err != nil {
		t.Fatal(err)
	}
	keys := jwks.Keys
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
		jwk  jwk.PublicKey
	}{
		{"EC P-256", jwk.PublicKey{CryptoPublicKey: &ecKey.PublicKey}},
		{"RSA 2048", jwk.PublicKey{CryptoPublicKey: &rsaKey.PublicKey}},
		{"Ed25519", jwk.PublicKey{CryptoPublicKey: edPub}},
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

	var jwks jwk.JWKs
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
