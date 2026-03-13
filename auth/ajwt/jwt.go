// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package ajwt is a lightweight JWT/JWS/JWK library designed from first
// principles:
//
//   - [JWS] is a parsed structure only — no Claims interface, no Verified flag.
//   - [Issuer] owns key management and signature verification, centralizing
//     the key lookup → sig verify → iss check sequence.
//   - [Validator] is a stable config object; time is passed at the call site
//     so the same validator can be reused across requests.
//   - [StandardClaimsSource] is implemented for free by embedding [StandardClaims].
//   - [JWS.UnmarshalClaims] accepts any type — no interface to implement.
//   - [JWS.Sign] uses [crypto.Signer] for ES256 (P-256), ES384 (P-384),
//     ES512 (P-521), RS256 (RSA PKCS#1 v1.5), and EdDSA (Ed25519/RFC 8037).
//
// Typical usage with VerifyAndValidate:
//
//	// At startup:
//	iss, err := ajwt.NewWithOIDC(ctx, "https://accounts.example.com",
//	    &ajwt.Validator{Aud: "my-app", IgnoreIss: true})
//
//	// Per request:
//	var claims AppClaims
//	jws, errs, err := iss.VerifyAndValidate(tokenStr, &claims, time.Now())
//	if err != nil { /* hard error: bad sig, expired, etc. */ }
//	if len(errs) > 0 { /* soft errors: wrong aud, missing amr, etc. */ }
//
// Typical usage with UnsafeVerify (custom validation only):
//
//	iss := ajwt.New("https://example.com", keys, nil)
//	jws, err := iss.UnsafeVerify(tokenStr)
//	var claims AppClaims
//	jws.UnmarshalClaims(&claims)
//	errs, err := ajwt.ValidateStandardClaims(claims.StandardClaims,
//	    ajwt.Validator{Aud: "myapp"}, time.Now())
package ajwt

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

// JWS is a decoded JSON Web Signature / JWT.
//
// It holds only the parsed structure — header, raw base64url fields, and
// decoded signature bytes. It carries no Claims interface and no Verified flag;
// use [Issuer.UnsafeVerify] or [Issuer.VerifyAndValidate] to authenticate the
// token and [JWS.UnmarshalClaims] to decode the payload into a typed struct.
type JWS struct {
	Protected string // base64url-encoded header
	Header    StandardHeader
	Payload   string // base64url-encoded claims
	Signature []byte
}

// StandardHeader holds the standard JOSE header fields.
type StandardHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

// StandardClaims holds the registered JWT claim names defined in RFC 7519
// and extended by OpenID Connect Core.
//
// Embed StandardClaims in your own claims struct to satisfy [StandardClaimsSource]
// for free via Go's method promotion — zero boilerplate:
//
//	type AppClaims struct {
//	    ajwt.StandardClaims        // promotes GetStandardClaims()
//	    Email string `json:"email"`
//	    Roles []string `json:"roles"`
//	}
//	// AppClaims now satisfies StandardClaimsSource automatically.
type StandardClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      string   `json:"aud"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce,omitempty"`
	Amr      []string `json:"amr"`
	Azp      string   `json:"azp,omitempty"`
	Jti      string   `json:"jti"`
}

// GetStandardClaims implements [StandardClaimsSource].
// Any struct embedding StandardClaims gets this method for free via promotion.
func (sc StandardClaims) GetStandardClaims() StandardClaims { return sc }

// StandardClaimsSource is implemented for free by any struct that embeds [StandardClaims].
//
//	type AppClaims struct {
//	    ajwt.StandardClaims        // promotes GetStandardClaims() — zero boilerplate
//	    Email string `json:"email"`
//	}
type StandardClaimsSource interface {
	GetStandardClaims() StandardClaims
}

// Decode parses a compact JWT string (header.payload.signature) into a JWS.
//
// It does not unmarshal the claims payload — call [JWS.UnmarshalClaims] after
// [Issuer.UnsafeVerify] to safely populate a typed claims struct.
func Decode(tokenStr string) (*JWS, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	var jws JWS
	jws.Protected, jws.Payload = parts[0], parts[1]

	header, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %v", err)
	}
	if err := json.Unmarshal(header, &jws.Header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %v", err)
	}

	jws.Signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %v", err)
	}

	return &jws, nil
}

// UnmarshalClaims decodes the JWT payload into v.
//
// v must be a pointer to a struct (e.g. *AppClaims). Always call
// [Issuer.UnsafeVerify] before UnmarshalClaims to ensure the signature is
// authenticated before trusting the payload.
func (jws *JWS) UnmarshalClaims(v any) error {
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return fmt.Errorf("invalid claims encoding: %v", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("invalid claims JSON: %v", err)
	}
	return nil
}

// NewJWSFromClaims creates an unsigned JWS from the provided claims.
//
// kid identifies the signing key. The "alg" header field is set automatically
// when [JWS.Sign] is called. Call [JWS.Encode] to produce the compact JWT
// string after signing.
func NewJWSFromClaims(claims any, kid string) (*JWS, error) {
	var jws JWS

	jws.Header = StandardHeader{
		// Alg is set by Sign based on the key type.
		Kid: kid,
		Typ: "JWT",
	}
	headerJSON, _ := json.Marshal(jws.Header)
	jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}
	jws.Payload = base64.RawURLEncoding.EncodeToString(claimsJSON)

	return &jws, nil
}

// Sign signs the JWS in-place using the provided [crypto.Signer].
// It sets the "alg" header field based on the public key type and re-encodes
// the protected header before signing, so the signed input is always
// consistent with the token header.
//
// Supported algorithms (inferred from key type):
//   - *ecdsa.PublicKey P-256  → ES256 (SHA-256, raw r||s)
//   - *ecdsa.PublicKey P-384  → ES384 (SHA-384, raw r||s)
//   - *ecdsa.PublicKey P-521  → ES512 (SHA-512, raw r||s)
//   - *rsa.PublicKey           → RS256 (PKCS#1 v1.5 + SHA-256)
//   - ed25519.PublicKey         → EdDSA (Ed25519, RFC 8037)
func (jws *JWS) Sign(key crypto.Signer) ([]byte, error) {
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		alg, h, err := algForECKey(pub)
		if err != nil {
			return nil, err
		}
		jws.Header.Alg = alg
		headerJSON, _ := json.Marshal(jws.Header)
		jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

		digest := digestFor(h, jws.Protected+"."+jws.Payload)
		// crypto.Signer returns ASN.1 DER for ECDSA; convert to raw r||s for JWS.
		derSig, err := key.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, fmt.Errorf("Sign %s: %w", alg, err)
		}
		jws.Signature, err = ecdsaDERToRaw(derSig, pub.Curve)
		return jws.Signature, err

	case *rsa.PublicKey:
		jws.Header.Alg = "RS256"
		headerJSON, _ := json.Marshal(jws.Header)
		jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

		digest := digestFor(crypto.SHA256, jws.Protected+"."+jws.Payload)
		// crypto.Signer returns raw PKCS#1 v1.5 bytes for RSA; use directly.
		var err error
		jws.Signature, err = key.Sign(rand.Reader, digest, crypto.SHA256)
		return jws.Signature, err

	case ed25519.PublicKey:
		jws.Header.Alg = "EdDSA"
		headerJSON, _ := json.Marshal(jws.Header)
		jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

		// Ed25519 signs the raw message with no pre-hashing; pass crypto.Hash(0).
		signingInput := jws.Protected + "." + jws.Payload
		var err error
		jws.Signature, err = key.Sign(rand.Reader, []byte(signingInput), crypto.Hash(0))
		return jws.Signature, err

	default:
		return nil, fmt.Errorf(
			"Sign: unsupported public key type %T (supported: *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey)",
			key.Public(),
		)
	}
}

// Encode produces the compact JWT string (header.payload.signature).
func (jws *JWS) Encode() string {
	return jws.Protected + "." + jws.Payload + "." + base64.RawURLEncoding.EncodeToString(jws.Signature)
}

// Validator holds claim validation configuration.
//
// Configure once at startup; call [Validator.Validate] per request, passing
// the current time. This keeps the config stable and makes the time dependency
// explicit at the call site.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type Validator struct {
	IgnoreIss      bool
	Iss            string // rarely needed — Issuer.UnsafeVerify already checks iss
	IgnoreSub      bool
	Sub            string
	IgnoreAud      bool
	Aud            string
	IgnoreExp      bool
	IgnoreJti      bool
	Jti            string
	IgnoreIat      bool
	IgnoreAuthTime bool
	MaxAge         time.Duration
	IgnoreNonce    bool
	Nonce          string
	IgnoreAmr      bool
	RequiredAmrs   []string
	IgnoreAzp      bool
	Azp            string
}

// Validate checks the standard JWT/OIDC claim fields in claims against this config.
//
// now is typically time.Now() — passing it explicitly keeps the config stable
// across requests and avoids hidden time dependencies in the validator struct.
func (v Validator) Validate(claims StandardClaimsSource, now time.Time) ([]string, error) {
	return ValidateStandardClaims(claims.GetStandardClaims(), v, now)
}

// ValidateStandardClaims checks the registered JWT/OIDC claim fields against v.
//
// Exported so callers can use it directly without a [Validator] receiver:
//
//	errs, err := ajwt.ValidateStandardClaims(claims.StandardClaims, v, time.Now())
func ValidateStandardClaims(claims StandardClaims, v Validator, now time.Time) ([]string, error) {
	var errs []string

	// Required to exist and match
	if len(v.Iss) > 0 || !v.IgnoreIss {
		if len(claims.Iss) == 0 {
			errs = append(errs, "missing or malformed 'iss' (token issuer, identifier for public key)")
		} else if claims.Iss != v.Iss {
			errs = append(errs, fmt.Sprintf("'iss' (token issuer) mismatch: got %s, expected %s", claims.Iss, v.Iss))
		}
	}

	// Required to exist, optional match
	if len(claims.Sub) == 0 {
		if !v.IgnoreSub {
			errs = append(errs, "missing or malformed 'sub' (subject, typically pairwise user id)")
		}
	} else if len(v.Sub) > 0 {
		if v.Sub != claims.Sub {
			errs = append(errs, fmt.Sprintf("'sub' (subject) mismatch: got %s, expected %s", claims.Sub, v.Sub))
		}
	}

	// Required to exist and match
	if len(v.Aud) > 0 || !v.IgnoreAud {
		if len(claims.Aud) == 0 {
			errs = append(errs, "missing or malformed 'aud' (audience receiving token)")
		} else if claims.Aud != v.Aud {
			errs = append(errs, fmt.Sprintf("'aud' (audience) mismatch: got %s, expected %s", claims.Aud, v.Aud))
		}
	}

	// Required to exist and not be in the past
	if !v.IgnoreExp {
		if claims.Exp <= 0 {
			errs = append(errs, "missing or malformed 'exp' (expiration date in seconds)")
		} else if claims.Exp < now.Unix() {
			duration := now.Sub(time.Unix(claims.Exp, 0))
			expTime := time.Unix(claims.Exp, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("token expired %s ago (%s)", formatDuration(duration), expTime))
		}
	}

	// Required to exist and not be in the future
	if !v.IgnoreIat {
		if claims.Iat <= 0 {
			errs = append(errs, "missing or malformed 'iat' (issued at, when token was signed)")
		} else if claims.Iat > now.Unix() {
			duration := time.Unix(claims.Iat, 0).Sub(now)
			iatTime := time.Unix(claims.Iat, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("'iat' (issued at) is %s in the future (%s)", formatDuration(duration), iatTime))
		}
	}

	// Should exist, in the past, with optional max age
	if v.MaxAge > 0 || !v.IgnoreAuthTime {
		if claims.AuthTime == 0 {
			errs = append(errs, "missing or malformed 'auth_time' (time of real-world user authentication, in seconds)")
		} else {
			authTime := time.Unix(claims.AuthTime, 0)
			authTimeStr := authTime.Format("2006-01-02 15:04:05 MST")
			age := now.Sub(authTime)
			diff := age - v.MaxAge
			if claims.AuthTime > now.Unix() {
				fromNow := time.Unix(claims.AuthTime, 0).Sub(now)
				errs = append(errs, fmt.Sprintf(
					"'auth_time' of %s is %s in the future (server time %s)",
					authTimeStr, formatDuration(fromNow), now.Format("2006-01-02 15:04:05 MST")),
				)
			} else if v.MaxAge > 0 && age > v.MaxAge {
				errs = append(errs, fmt.Sprintf(
					"'auth_time' of %s is %s old, exceeding max age %s by %s",
					authTimeStr, formatDuration(age), formatDuration(v.MaxAge), formatDuration(diff)),
				)
			}
		}
	}

	// Optional exact match
	if v.Jti != claims.Jti {
		if len(v.Jti) > 0 {
			errs = append(errs, fmt.Sprintf("'jti' (jwt id) mismatch: got %s, expected %s", claims.Jti, v.Jti))
		} else if !v.IgnoreJti {
			errs = append(errs, fmt.Sprintf("unchecked 'jti' (jwt id): %s", claims.Jti))
		}
	}

	// Optional exact match
	if v.Nonce != claims.Nonce {
		if len(v.Nonce) > 0 {
			errs = append(errs, fmt.Sprintf("'nonce' mismatch: got %s, expected %s", claims.Nonce, v.Nonce))
		} else if !v.IgnoreNonce {
			errs = append(errs, fmt.Sprintf("unchecked 'nonce': %s", claims.Nonce))
		}
	}

	// Should exist, optional required-set check
	if !v.IgnoreAmr {
		if len(claims.Amr) == 0 {
			errs = append(errs, "missing or malformed 'amr' (authorization methods, as json list)")
		} else if len(v.RequiredAmrs) > 0 {
			for _, required := range v.RequiredAmrs {
				if !slices.Contains(claims.Amr, required) {
					errs = append(errs, fmt.Sprintf("missing required '%s' from 'amr'", required))
				}
			}
		}
	}

	// Optional, match if present
	if v.Azp != claims.Azp {
		if len(v.Azp) > 0 {
			errs = append(errs, fmt.Sprintf("'azp' (authorized party) mismatch: got %s, expected %s", claims.Azp, v.Azp))
		} else if !v.IgnoreAzp {
			errs = append(errs, fmt.Sprintf("unchecked 'azp' (authorized party): %s", claims.Azp))
		}
	}

	if len(errs) > 0 {
		timeInfo := fmt.Sprintf("info: server time is %s", now.Format("2006-01-02 15:04:05 MST"))
		if loc, err := time.LoadLocation("Local"); err == nil {
			timeInfo += fmt.Sprintf(" %s", loc)
		}
		errs = append(errs, timeInfo)
		return errs, fmt.Errorf("has errors")
	}
	return nil, nil
}

// Issuer holds public keys and optional validation config for a trusted token issuer.
//
// Create with [New], [NewWithJWKs], [NewWithOIDC], or [NewWithOAuth2].
// After construction, Issuer is immutable.
//
// [Issuer.UnsafeVerify] authenticates the token: Decode + key lookup + sig verify + iss check.
// [Issuer.VerifyAndValidate] additionally unmarshals claims and runs the Validator.
type Issuer struct {
	URL       string // issuer URL for iss claim enforcement; empty skips the check
	validator *Validator
	keys      map[string]crypto.PublicKey // kid → key
}

// New creates an Issuer with explicit keys.
//
// v is optional — pass nil to use [Issuer.UnsafeVerify] only.
// [Issuer.VerifyAndValidate] requires a non-nil Validator.
func New(issURL string, keys []PublicJWK, v *Validator) *Issuer {
	m := make(map[string]crypto.PublicKey, len(keys))
	for _, k := range keys {
		m[k.KID] = k.Key
	}
	return &Issuer{
		URL:       issURL,
		validator: v,
		keys:      m,
	}
}

// NewWithJWKs creates an Issuer by fetching keys from jwksURL.
//
// The issuer URL (used for iss claim enforcement in [Issuer.UnsafeVerify]) is
// not set; use [New] or [NewWithOIDC]/[NewWithOAuth2] if you need iss enforcement.
//
// v is optional — pass nil to use [Issuer.UnsafeVerify] only.
func NewWithJWKs(ctx context.Context, jwksURL string, v *Validator) (*Issuer, error) {
	keys, err := FetchJWKs(ctx, jwksURL)
	if err != nil {
		return nil, err
	}
	return New("", keys, v), nil
}

// NewWithOIDC creates an Issuer using OIDC discovery.
//
// It fetches {baseURL}/.well-known/openid-configuration and reads the
// jwks_uri and issuer fields. The Issuer URL is set from the discovery
// document's issuer field (not baseURL) because OIDC requires them to match.
//
// v is optional — pass nil to use [Issuer.UnsafeVerify] only.
func NewWithOIDC(ctx context.Context, baseURL string, v *Validator) (*Issuer, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/openid-configuration"
	keys, issURL, err := fetchJWKsFromDiscovery(ctx, discoveryURL)
	if err != nil {
		return nil, err
	}
	return New(issURL, keys, v), nil
}

// NewWithOAuth2 creates an Issuer using OAuth 2.0 authorization server metadata (RFC 8414).
//
// It fetches {baseURL}/.well-known/oauth-authorization-server and reads the
// jwks_uri and issuer fields. The Issuer URL is set from the discovery
// document's issuer field.
//
// v is optional — pass nil to use [Issuer.UnsafeVerify] only.
func NewWithOAuth2(ctx context.Context, baseURL string, v *Validator) (*Issuer, error) {
	discoveryURL := strings.TrimRight(baseURL, "/") + "/.well-known/oauth-authorization-server"
	keys, issURL, err := fetchJWKsFromDiscovery(ctx, discoveryURL)
	if err != nil {
		return nil, err
	}
	return New(issURL, keys, v), nil
}

// UnsafeVerify decodes tokenStr, verifies the signature, and (if [Issuer.URL]
// is set) checks the iss claim.
//
// "Unsafe" means exp, aud, and other claim values are NOT checked — the token
// is forgery-safe but not semantically validated. Callers are responsible for
// validating claim values, or use [Issuer.VerifyAndValidate].
func (iss *Issuer) UnsafeVerify(tokenStr string) (*JWS, error) {
	jws, err := Decode(tokenStr)
	if err != nil {
		return nil, err
	}

	if jws.Header.Kid == "" {
		return nil, fmt.Errorf("missing 'kid' header")
	}
	key, ok := iss.keys[jws.Header.Kid]
	if !ok {
		return nil, fmt.Errorf("unknown kid: %q", jws.Header.Kid)
	}

	signingInput := jws.Protected + "." + jws.Payload
	if err := verifyWith(signingInput, jws.Signature, jws.Header.Alg, key); err != nil {
		return nil, fmt.Errorf("signature verification failed: %w", err)
	}

	// Signature verified — now safe to inspect the payload for iss check.
	if iss.URL != "" {
		payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
		if err != nil {
			return nil, fmt.Errorf("invalid claims encoding: %w", err)
		}
		var partial struct {
			Iss string `json:"iss"`
		}
		if err := json.Unmarshal(payload, &partial); err != nil {
			return nil, fmt.Errorf("invalid claims JSON: %w", err)
		}
		if partial.Iss != iss.URL {
			return nil, fmt.Errorf("iss mismatch: got %q, want %q", partial.Iss, iss.URL)
		}
	}

	return jws, nil
}

// VerifyAndValidate verifies the token signature and iss, unmarshals the claims
// into claims, and runs the [Validator].
//
// Returns a hard error (err != nil) for signature failures, decoding errors,
// and nil Validator. Returns soft errors (errs != nil) for claim validation
// failures (wrong aud, expired token, etc.).
//
// claims must be a pointer whose underlying type embeds [StandardClaims] (or
// otherwise implements [StandardClaimsSource]):
//
//	var claims AppClaims
//	jws, errs, err := iss.VerifyAndValidate(tokenStr, &claims, time.Now())
func (iss *Issuer) VerifyAndValidate(tokenStr string, claims StandardClaimsSource, now time.Time) (*JWS, []string, error) {
	if iss.validator == nil {
		return nil, nil, fmt.Errorf("VerifyAndValidate requires a non-nil Validator; use UnsafeVerify for signature-only verification")
	}

	jws, err := iss.UnsafeVerify(tokenStr)
	if err != nil {
		return nil, nil, err
	}

	if err := jws.UnmarshalClaims(claims); err != nil {
		return nil, nil, err
	}

	errs, err := iss.validator.Validate(claims, now)
	return jws, errs, err
}

// verifyWith checks a JWS signature using the given algorithm and public key.
// Returns nil on success, a descriptive error on failure.
func verifyWith(signingInput string, sig []byte, alg string, key crypto.PublicKey) error {
	switch alg {
	case "ES256", "ES384", "ES512":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg %s requires *ecdsa.PublicKey, got %T", alg, key)
		}
		expectedAlg, h, err := algForECKey(k)
		if err != nil {
			return err
		}
		if expectedAlg != alg {
			return fmt.Errorf("key curve mismatch: key is %s, token alg is %s", expectedAlg, alg)
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*byteLen {
			return fmt.Errorf("invalid %s signature length: got %d, want %d", alg, len(sig), 2*byteLen)
		}
		digest := digestFor(h, signingInput)
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		if !ecdsa.Verify(k, digest, r, s) {
			return fmt.Errorf("%s signature invalid", alg)
		}
		return nil

	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg RS256 requires *rsa.PublicKey, got %T", key)
		}
		digest := digestFor(crypto.SHA256, signingInput)
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig); err != nil {
			return fmt.Errorf("RS256 signature invalid: %w", err)
		}
		return nil

	case "EdDSA":
		k, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("alg EdDSA requires ed25519.PublicKey, got %T", key)
		}
		if !ed25519.Verify(k, []byte(signingInput), sig) {
			return fmt.Errorf("EdDSA signature invalid")
		}
		return nil

	default:
		return fmt.Errorf("unsupported alg: %q", alg)
	}
}

// --- Internal helpers ---

func algForECKey(pub *ecdsa.PublicKey) (alg string, h crypto.Hash, err error) {
	switch pub.Curve {
	case elliptic.P256():
		return "ES256", crypto.SHA256, nil
	case elliptic.P384():
		return "ES384", crypto.SHA384, nil
	case elliptic.P521():
		return "ES512", crypto.SHA512, nil
	default:
		return "", 0, fmt.Errorf("unsupported EC curve: %s", pub.Curve.Params().Name)
	}
}

func digestFor(h crypto.Hash, data string) []byte {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256([]byte(data))
		return d[:]
	case crypto.SHA384:
		d := sha512.Sum384([]byte(data))
		return d[:]
	case crypto.SHA512:
		d := sha512.Sum512([]byte(data))
		return d[:]
	default:
		panic(fmt.Sprintf("ajwt: unsupported hash %v", h))
	}
}

func ecdsaDERToRaw(der []byte, curve elliptic.Curve) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	if _, err := asn1.Unmarshal(der, &sig); err != nil {
		return nil, fmt.Errorf("ecdsaDERToRaw: %w", err)
	}
	byteLen := (curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*byteLen)
	sig.R.FillBytes(out[:byteLen])
	sig.S.FillBytes(out[byteLen:])
	return out, nil
}

func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int(d / time.Minute)
	d -= time.Duration(minutes) * time.Minute
	seconds := int(d / time.Second)

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 || len(parts) == 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	if seconds == 0 || len(parts) == 0 {
		d -= time.Duration(seconds) * time.Second
		millis := int(d / time.Millisecond)
		parts = append(parts, fmt.Sprintf("%dms", millis))
	}

	return strings.Join(parts, " ")
}
