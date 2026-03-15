// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt_test

import (
	"context"
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

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jose"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// AppClaims embeds IDTokenClaims and adds application-specific fields.
//
// Because IDTokenClaims is embedded, AppClaims satisfies Claims
// for free via Go's method promotion - no interface to implement.
type AppClaims struct {
	jwt.IDTokenClaims
	Email string   `json:"email"`
	Roles []string `json:"roles"`
}

// validateAppClaims is a plain function - not a method satisfying an interface.
// It demonstrates the Decode+Verify pattern: custom validation logic lives here,
// calling Validator.Validate and adding app-specific checks.
func validateAppClaims(c AppClaims, v *jwt.IDTokenValidator, now time.Time) error {
	var errs []error
	if _, err := v.Validate(&c, now); err != nil {
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
		IDTokenClaims: jwt.IDTokenClaims{
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

// goodValidator configures the ID token validator with iss set to "https://example.com".
// Iss checking is now the Validator's responsibility, not the Verifier's.
func goodValidator() *jwt.IDTokenValidator {
	return &jwt.IDTokenValidator{
		Iss:          []string{"https://example.com"},
		Aud:          []string{"myapp"},
		Azp:          []string{"myapp"},
		RequiredAMRs: []string{"pwd"},
	}
}

func goodVerifier(pub jwk.PublicKey) *jwt.Verifier {
	v, err := jwt.NewVerifier([]jwk.PublicKey{pub})
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

	signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "key-1", Signer: privKey}})
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

	token := jwt.Encode(jws)

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	if jws2.GetHeader().Alg != "ES256" {
		t.Errorf("expected ES256 alg in jws, got %s", jws2.GetHeader().Alg)
	}

	var decoded AppClaims
	if err := jwt.UnmarshalClaims(jws2, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if _, err := goodValidator().Validate(&decoded, time.Now()); err != nil {
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

	signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "key-1", Signer: privKey}})
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

	token := jwt.Encode(jws)

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jwt.UnmarshalClaims(jws2, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if _, err := goodValidator().Validate(&decoded, time.Now()); err != nil {
		t.Fatalf("claim validation failed: %v", err)
	}
}

// TestRoundTripEdDSA exercises Ed25519 / EdDSA (RFC 8037).
func TestRoundTripEdDSA(t *testing.T) {
	pubKeyBytes, privKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]jwk.PrivateKey{{KID: "key-1", Signer: privKey}})
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

	token := jwt.Encode(jws)

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: pubKeyBytes, KID: "key-1"})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var decoded AppClaims
	if err := jwt.UnmarshalClaims(jws2, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if _, err := goodValidator().Validate(&decoded, time.Now()); err != nil {
		t.Fatalf("claim validation failed: %v", err)
	}
}

// TestDecodeVerifyFlow demonstrates the Decode + Verify + custom validation pattern.
// The caller owns the full validation pipeline.
func TestDecodeVerifyFlow(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{{KID: "k", Signer: privKey}})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	iss, _ := jwt.NewVerifier([]jwk.PublicKey{{CryptoPublicKey: &privKey.PublicKey, KID: "k"}})

	jws2, err := jwt.Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if err := iss.Verify(jws2); err != nil {
		t.Fatalf("Verify failed: %v", err)
	}

	var decoded AppClaims
	if err := jwt.UnmarshalClaims(jws2, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}

	if _, err := goodValidator().Validate(&decoded, time.Now()); err != nil {
		t.Fatalf("Validate failed: %v", err)
	}
}

// TestDecodeReturnsParsedOnSigFailure verifies that Decode returns a non-nil
// *StandardJWS even when the token will later fail signature verification.
// Callers can inspect the header (kid, alg) for routing before calling Verify.
func TestDecodeReturnsParsedOnSigFailure(t *testing.T) {
	signingKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	wrongKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{{KID: "k", Signer: signingKey}})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	// Verifier has wrong public key - sig verification will fail.
	iss, _ := jwt.NewVerifier([]jwk.PublicKey{{CryptoPublicKey: &wrongKey.PublicKey, KID: "k"}})

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
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{{KID: "k", Signer: privKey}})
	claims := goodClaims()
	claims.Email = ""
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "k"})
	jws2, err := jwt.Decode(token)
	if err != nil {
		t.Fatalf("Decode failed: %v", err)
	}
	if err := iss.Verify(jws2); err != nil {
		t.Fatalf("Verify failed unexpectedly: %v", err)
	}

	var decoded AppClaims
	_ = jwt.UnmarshalClaims(jws2, &decoded)

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
		IDTokenClaims: jwt.IDTokenClaims{
			Iss: "https://example.com",
			Aud: jwt.Audience{"myapp"},
			Exp: now.Add(time.Hour).Unix(),
			Iat: now.Unix(),
		},
	}

	v := &jwt.IDTokenValidator{
		Iss:       []string{"https://example.com"},
		Aud:       []string{"myapp"},
		IgnoreSub: true,
	}

	// No nbf: should pass.
	if _, err := v.Validate(&base, now); err != nil {
		t.Fatalf("expected no error without nbf: %v", err)
	}

	// nbf in the past: should pass.
	pastNBF := base
	pastNBF.NBF = now.Add(-time.Hour).Unix()
	if _, err := v.Validate(&pastNBF, now); err != nil {
		t.Fatalf("expected no error with past nbf: %v", err)
	}

	// nbf in the future: must be rejected.
	futureNBF := base
	futureNBF.NBF = now.Add(time.Hour).Unix()
	_, err := v.Validate(&futureNBF, now)
	if err == nil {
		t.Fatal("expected error for future nbf")
	}
	if !errors.Is(err, jose.ErrBeforeNbf) {
		t.Fatalf("expected ErrBeforeNbf, got: %v", err)
	}
}

// TestVerifyWithoutValidation confirms that Verify + UnmarshalClaims succeeds
// independently of claim validation - the caller decides whether to validate.
func TestVerifyWithoutValidation(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{{KID: "k", Signer: privKey}})
	c := goodClaims()
	token, _ := signer.SignToString(&c)

	iss, _ := jwt.NewVerifier([]jwk.PublicKey{{CryptoPublicKey: &privKey.PublicKey, KID: "k"}})

	jws2, err := iss.VerifyJWT(token)
	if err != nil {
		t.Fatalf("VerifyJWT failed: %v", err)
	}
	var claims AppClaims
	if err := jwt.UnmarshalClaims(jws2, &claims); err != nil {
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
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{{KID: "k", Signer: signingKey}})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &wrongKey.PublicKey, KID: "k"})

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); !errors.Is(err, jose.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}
}

// TestVerifierUnknownKid confirms that an unknown kid is rejected.
func TestVerifierUnknownKid(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{{KID: "unknown-kid", Signer: privKey}})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "known-kid"})

	parsed, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); !errors.Is(err, jose.ErrUnknownKID) {
		t.Fatalf("expected ErrUnknownKID, got: %v", err)
	}
}

// TestVerifierIssMismatch confirms that a token with a mismatched iss is caught
// by the Validator, not the Verifier. Signature verification succeeds; the iss
// mismatch appears as a soft validation error.
func TestVerifierIssMismatch(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{{KID: "k", Signer: privKey}})

	claims := goodClaims()
	claims.Iss = "https://evil.example.com"
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "k"})

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
	if err := jwt.UnmarshalClaims(jws2, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	_, err = goodValidator().Validate(&decoded, time.Now())
	if err == nil {
		t.Fatal("expected validation errors for iss mismatch")
	}
	if !errors.Is(err, jose.ErrInvalidClaim) {
		t.Fatalf("expected ErrInvalidClaim for iss mismatch, got: %v", err)
	}
}

// TestVerifyTamperedAlg confirms that a tampered alg header ("none") is rejected.
// The token is reconstructed with a replaced protected header; the original
// ES256 signature is kept, making the signing input mismatch detectable.
func TestVerifyTamperedAlg(t *testing.T) {
	privKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{{KID: "k", Signer: privKey}})

	claims := goodClaims()
	token, _ := signer.SignToString(&claims)

	iss := goodVerifier(jwk.PublicKey{CryptoPublicKey: &privKey.PublicKey, KID: "k"})

	// Replace the protected header with one that has alg:"none".
	// The original ES256 signature stays - the signing input will mismatch.
	noneHeader := base64.RawURLEncoding.EncodeToString([]byte(`{"alg":"none","kid":"k","typ":"JWT"}`))
	parts := strings.SplitN(token, ".", 3)
	tamperedToken := noneHeader + "." + parts[1] + "." + parts[2]

	parsed, err := jwt.Decode(tamperedToken)
	if err != nil {
		t.Fatal(err)
	}
	if err := iss.Verify(parsed); !errors.Is(err, jose.ErrUnsupportedAlg) {
		t.Fatalf("expected ErrUnsupportedAlg for tampered alg, got: %v", err)
	}
}

// TestSignerRoundTrip verifies the Signer / Sign / Verifier / Verify / Validate flow.
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
	if err := jwt.UnmarshalClaims(jws, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims failed: %v", err)
	}
	if _, err := goodValidator().Validate(&decoded, time.Now()); err != nil {
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
		if err := jwt.UnmarshalClaims(jws, &decoded); err != nil {
			t.Fatalf("UnmarshalClaims[%d] failed: %v", i, err)
		}
		if _, err := v.Validate(&decoded, time.Now()); err != nil {
			t.Fatalf("Validate[%d] failed: %v", i, err)
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
		key     jwk.PublicKey
		wantKty string
	}{
		{"EC P-256", jwk.PublicKey{CryptoPublicKey: &ecKey.PublicKey}, "EC"},
		{"RSA 2048", jwk.PublicKey{CryptoPublicKey: &rsaKey.PublicKey}, "RSA"},
		{"Ed25519", jwk.PublicKey{CryptoPublicKey: edPub}, "OKP"},
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
	base, err := jwk.NewPrivateKey()
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
			// Same key, same thumbprint
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

// TestNewPrivateKey verifies that jwk.NewPrivateKey generates an Ed25519 key
// with a non-empty KID auto-derived from the thumbprint, and that the key
// works end-to-end for signing and verification.
func TestNewPrivateKey(t *testing.T) {
	pk, err := jwk.NewPrivateKey()
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
	pk2, _ := jwk.NewPrivateKey()
	if pk.KID == pk2.KID {
		t.Error("NewPrivateKey() produced identical KIDs for two different keys")
	}

	// Full sign+verify round-trip with the generated key.
	signer, err := jwt.NewSigner([]jwk.PrivateKey{*pk})
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
	if err := jwt.UnmarshalClaims(jws, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims() error: %v", err)
	}
	if decoded.Sub != claims.Sub {
		t.Errorf("sub: got %q, want %q", decoded.Sub, claims.Sub)
	}
}

// --- DecodeRaw + UnmarshalHeader tests ---

func TestDecodeRaw(t *testing.T) {
	// Sign a real token to get a valid compact string.
	pk, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error: %v", err)
	}
	signer, err := jwt.NewSigner([]jwk.PrivateKey{*pk})
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
		{"empty string", "", jose.ErrMalformedToken},
		{"one segment", "abc", jose.ErrMalformedToken},
		{"two segments", "abc.def", jose.ErrMalformedToken},
		{"four segments", "a.b.c.d", jose.ErrMalformedToken},
		{"bad signature base64", "eyJhbGciOiJFZERTQSJ9.eyJpc3MiOiJ4In0.!!!bad!!!", jose.ErrSignatureInvalid},
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
	pk, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error: %v", err)
	}
	signer, err := jwt.NewSigner([]jwk.PrivateKey{*pk})
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

	var h jwt.Header
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
		jwt.Header
		Nonce string `json:"nonce"`
	}

	hdr := CustomHeader{
		Header: jwt.Header{Alg: "EdDSA", KID: "test-key", Typ: "dpop+jwt"},
		Nonce:  "server-nonce-42",
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
	// Verify that UnmarshalHeader is promoted from RawJWT to *JWS.
	pk, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatalf("NewPrivateKey() error: %v", err)
	}
	signer, err := jwt.NewSigner([]jwk.PrivateKey{*pk})
	if err != nil {
		t.Fatalf("NewSigner() error: %v", err)
	}
	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatalf("SignToString() error: %v", err)
	}

	// Use Decode (not DecodeRaw) — UnmarshalHeader should still work via promotion.
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatalf("Decode() error: %v", err)
	}

	var h jwt.Header
	if err := jws.UnmarshalHeader(&h); err != nil {
		t.Fatalf("jws.UnmarshalHeader() error: %v", err)
	}
	if h.Alg != "EdDSA" {
		t.Errorf("alg: got %q, want %q", h.Alg, "EdDSA")
	}
}

// --- Scope tests ---

func TestScopeMarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		in   jwt.Scope
		want string
	}{
		{"multiple", jwt.Scope{"openid", "profile", "email"}, `"openid profile email"`},
		{"single", jwt.Scope{"openid"}, `"openid"`},
		{"empty", jwt.Scope{}, `""`},
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

func TestScopeUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		in      string
		want    jwt.Scope
		wantNil bool
	}{
		{"multiple", `"openid profile email"`, jwt.Scope{"openid", "profile", "email"}, false},
		{"single", `"openid"`, jwt.Scope{"openid"}, false},
		{"empty", `""`, nil, true},
		{"extra whitespace", `"openid  profile\temail"`, jwt.Scope{"openid", "profile", "email"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got jwt.Scope
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

func TestScopeRoundTrip(t *testing.T) {
	type claims struct {
		Scope jwt.Scope `json:"scope,omitempty"`
	}
	orig := claims{Scope: jwt.Scope{"openid", "profile"}}
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
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "user1",
		Aud: jwt.Audience{"api"},
		Exp: time.Now().Add(time.Hour).Unix(),
		Iat: time.Now().Unix(),
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
	signer, err := jwt.NewSigner([]jwk.PrivateKey{{Signer: priv}})
	if err != nil {
		t.Fatal(err)
	}

	now := time.Now()
	claims := &jwt.AccessTokenClaims{
		Iss:      "https://auth.example.com",
		Sub:      "user1",
		Aud:      jwt.Audience{"https://api.example.com"},
		Exp:      now.Add(time.Hour).Unix(),
		Iat:      now.Unix(),
		JTI:      "tok-001",
		ClientID: "webapp",
		Scope:    jwt.Scope{"openid", "profile"},
	}

	jws, err := jwt.NewAccessToken(claims)
	if err != nil {
		t.Fatal(err)
	}
	if err := signer.SignJWS(jws); err != nil {
		t.Fatal(err)
	}

	// Verify typ survived signing.
	if got := jws.GetHeader().Typ; got != jwt.AccessTokenTyp {
		t.Fatalf("typ after signing: got %q, want %q", got, jwt.AccessTokenTyp)
	}

	// Decode the token and verify typ is in the wire format.
	token := jwt.Encode(jws)
	decoded, err := jwt.Decode(token)
	if err != nil {
		t.Fatal(err)
	}
	if got := decoded.GetHeader().Typ; got != jwt.AccessTokenTyp {
		t.Fatalf("typ after decode: got %q, want %q", got, jwt.AccessTokenTyp)
	}

	// Verify claims round-trip.
	var rt jwt.AccessTokenClaims
	if err := jwt.UnmarshalClaims(decoded, &rt); err != nil {
		t.Fatal(err)
	}
	if rt.ClientID != "webapp" {
		t.Errorf("client_id: got %q, want %q", rt.ClientID, "webapp")
	}
	if len(rt.Scope) != 2 || rt.Scope[0] != "openid" {
		t.Errorf("scope: got %v, want [openid profile]", rt.Scope)
	}
}

// --- AccessTokenValidator tests ---

func goodAccessTokenClaims() *jwt.AccessTokenClaims {
	now := time.Now()
	return &jwt.AccessTokenClaims{
		Iss:      "https://auth.example.com",
		Sub:      "user1",
		Aud:      jwt.Audience{"https://api.example.com"},
		Exp:      now.Add(time.Hour).Unix(),
		Iat:      now.Unix(),
		JTI:      "tok-001",
		ClientID: "webapp",
		Scope:    jwt.Scope{"openid", "profile"},
		AMR:      []string{"pwd"},
	}
}

func TestAccessTokenValidatorHappyPath(t *testing.T) {
	v := &jwt.AccessTokenValidator{
		Iss: []string{"https://auth.example.com"},
		Aud: []string{"https://api.example.com"},
	}
	claims := goodAccessTokenClaims()
	if _, err := v.Validate(claims, time.Now()); err != nil {
		t.Fatalf("valid access token rejected: %v", err)
	}
}

func TestAccessTokenValidatorRequiresJTI(t *testing.T) {
	v := &jwt.AccessTokenValidator{
		Iss: []string{"https://auth.example.com"},
		Aud: []string{"https://api.example.com"},
	}
	claims := goodAccessTokenClaims()
	claims.JTI = ""
	_, err := v.Validate(claims, time.Now())
	if !errors.Is(err, jose.ErrMissingClaim) {
		t.Fatalf("expected ErrMissingClaim for missing jti, got: %v", err)
	}
}

func TestAccessTokenValidatorRequiresClientID(t *testing.T) {
	v := &jwt.AccessTokenValidator{
		Iss: []string{"https://auth.example.com"},
		Aud: []string{"https://api.example.com"},
	}
	claims := goodAccessTokenClaims()
	claims.ClientID = ""
	_, err := v.Validate(claims, time.Now())
	if !errors.Is(err, jose.ErrMissingClaim) {
		t.Fatalf("expected ErrMissingClaim for missing client_id, got: %v", err)
	}
}

func TestAccessTokenValidatorIgnoreClientID(t *testing.T) {
	v := &jwt.AccessTokenValidator{
		Iss:            []string{"https://auth.example.com"},
		Aud:            []string{"https://api.example.com"},
		IgnoreClientID: true,
	}
	claims := goodAccessTokenClaims()
	claims.ClientID = ""
	if _, err := v.Validate(claims, time.Now()); err != nil {
		t.Fatalf("IgnoreClientID=true should accept empty client_id: %v", err)
	}
}

func TestAccessTokenValidatorExpiredToken(t *testing.T) {
	v := &jwt.AccessTokenValidator{
		Iss: []string{"https://auth.example.com"},
		Aud: []string{"https://api.example.com"},
	}
	claims := goodAccessTokenClaims()
	claims.Exp = time.Now().Add(-time.Hour).Unix()
	_, err := v.Validate(claims, time.Now())
	if !errors.Is(err, jose.ErrAfterExp) {
		t.Fatalf("expected ErrAfterExp, got: %v", err)
	}
}

func TestAccessTokenValidatorRequiredScopes(t *testing.T) {
	v := &jwt.AccessTokenValidator{
		Iss:            []string{"https://auth.example.com"},
		Aud:            []string{"https://api.example.com"},
		RequiredScopes: []string{"openid", "admin"},
	}
	claims := goodAccessTokenClaims()
	// claims has ["openid", "profile"] — missing "admin"
	_, err := v.Validate(claims, time.Now())
	if !errors.Is(err, jose.ErrInvalidClaim) {
		t.Fatalf("expected ErrInvalidClaim for missing scope, got: %v", err)
	}
}

func TestAccessTokenValidatorExpectScope(t *testing.T) {
	v := &jwt.AccessTokenValidator{
		Iss:         []string{"https://auth.example.com"},
		Aud:         []string{"https://api.example.com"},
		ExpectScope: true,
	}
	claims := goodAccessTokenClaims()
	claims.Scope = nil
	_, err := v.Validate(claims, time.Now())
	if !errors.Is(err, jose.ErrMissingClaim) {
		t.Fatalf("expected ErrMissingClaim for empty scope, got: %v", err)
	}
}

func TestAccessTokenValidatorIgnoreJTI(t *testing.T) {
	v := &jwt.AccessTokenValidator{
		Iss:       []string{"https://auth.example.com"},
		Aud:       []string{"https://api.example.com"},
		IgnoreJTI: true,
	}
	claims := goodAccessTokenClaims()
	claims.JTI = ""
	if _, err := v.Validate(claims, time.Now()); err != nil {
		t.Fatalf("IgnoreJTI=true should accept empty jti: %v", err)
	}
}

// --- Context accessor tests ---

func TestIDTokenClaimsContext(t *testing.T) {
	claims := &jwt.IDTokenClaims{
		Iss: "https://auth.example.com",
		Sub: "user-123",
	}
	ctx := jwt.WithIDTokenClaims(context.Background(), claims)

	got, ok := jwt.IDTokenClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true from IDTokenClaimsFromContext")
	}
	if got.Sub != "user-123" {
		t.Fatalf("Sub = %q, want %q", got.Sub, "user-123")
	}

	// Empty context returns nil, false.
	got, ok = jwt.IDTokenClaimsFromContext(context.Background())
	if ok || got != nil {
		t.Fatal("expected nil, false from empty context")
	}
}

func TestAccessTokenClaimsContext(t *testing.T) {
	claims := &jwt.AccessTokenClaims{
		Iss:      "https://auth.example.com",
		Sub:      "user-456",
		ClientID: "my-client",
	}
	ctx := jwt.WithAccessTokenClaims(context.Background(), claims)

	got, ok := jwt.AccessTokenClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true from AccessTokenClaimsFromContext")
	}
	if got.ClientID != "my-client" {
		t.Fatalf("ClientID = %q, want %q", got.ClientID, "my-client")
	}

	// Empty context returns nil, false.
	got, ok = jwt.AccessTokenClaimsFromContext(context.Background())
	if ok || got != nil {
		t.Fatal("expected nil, false from empty context")
	}
}

func TestStandardClaimsContext(t *testing.T) {
	claims := &jwt.StandardClaims{
		Name:  "Test User",
		Email: "test@example.com",
	}
	claims.Iss = "https://auth.example.com"
	claims.Sub = "user-789"
	ctx := jwt.WithStandardClaims(context.Background(), claims)

	got, ok := jwt.StandardClaimsFromContext(ctx)
	if !ok {
		t.Fatal("expected ok=true from StandardClaimsFromContext")
	}
	if got.Email != "test@example.com" {
		t.Fatalf("Email = %q, want %q", got.Email, "test@example.com")
	}

	// Empty context returns nil, false.
	got, ok = jwt.StandardClaimsFromContext(context.Background())
	if ok || got != nil {
		t.Fatal("expected nil, false from empty context")
	}
}

func TestContextKeysAreDistinct(t *testing.T) {
	idClaims := &jwt.IDTokenClaims{Sub: "id-user"}
	atClaims := &jwt.AccessTokenClaims{Sub: "at-user"}
	stdClaims := &jwt.StandardClaims{}
	stdClaims.Sub = "std-user"

	ctx := context.Background()
	ctx = jwt.WithIDTokenClaims(ctx, idClaims)
	ctx = jwt.WithAccessTokenClaims(ctx, atClaims)
	ctx = jwt.WithStandardClaims(ctx, stdClaims)

	id, _ := jwt.IDTokenClaimsFromContext(ctx)
	at, _ := jwt.AccessTokenClaimsFromContext(ctx)
	std, _ := jwt.StandardClaimsFromContext(ctx)

	if id.Sub != "id-user" {
		t.Fatalf("IDToken Sub = %q, want %q", id.Sub, "id-user")
	}
	if at.Sub != "at-user" {
		t.Fatalf("AccessToken Sub = %q, want %q", at.Sub, "at-user")
	}
	if std.Sub != "std-user" {
		t.Fatalf("Standard Sub = %q, want %q", std.Sub, "std-user")
	}
}
