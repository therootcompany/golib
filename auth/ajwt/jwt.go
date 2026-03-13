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
//   - [Issuer] is immutable — constructed with a fixed key set, safe for concurrent use.
//   - [Signer] manages private keys and returns [*Issuer] for verification.
//   - [JWKsFetcher] lazily fetches and caches JWKS keys, returning a fresh [*Issuer] on demand.
//   - [Validator] and [MultiValidator] validate standard JWT/OIDC claims.
//   - [JWS] is a parsed structure — use [Issuer.Verify] or [Issuer.UnsafeVerify] to authenticate.
//   - [JWS.UnmarshalClaims] accepts any type — no Claims interface to implement.
//   - [StandardClaimsSource] is satisfied for free by embedding [StandardClaims].
//
// Typical usage with VerifyAndValidate:
//
//	// At startup:
//	signer, err := ajwt.NewSigner([]ajwt.NamedSigner{{Signer: privKey}})
//	iss := signer.Issuer()
//	v := &ajwt.Validator{Iss: "https://example.com", Aud: "my-app"}
//
//	// Sign a token:
//	tokenStr, err := signer.Sign(claims)
//
//	// Per request:
//	var claims AppClaims
//	jws, errs, err := iss.VerifyAndValidate(tokenStr, &claims, v, time.Now())
//	if err != nil { /* hard error: bad sig, malformed token */ }
//	if len(errs) > 0 { /* soft errors: wrong aud, expired, etc. */ }
//
// Typical usage with UnsafeVerify (custom validation):
//
//	iss := ajwt.New(keys)
//	jws, err := iss.UnsafeVerify(tokenStr)
//	var claims AppClaims
//	jws.UnmarshalClaims(&claims)
//	errs, err := ajwt.ValidateStandardClaims(claims.StandardClaims,
//	    ajwt.Validator{Aud: "myapp"}, time.Now())
//
// Typical usage with JWKsFetcher (dynamic keys from remote):
//
//	fetcher := &ajwt.JWKsFetcher{
//	    URL:         "https://accounts.example.com/.well-known/jwks.json",
//	    MaxAge:      time.Hour,
//	    StaleAge:    time.Hour,
//	    KeepOnError: true,
//	}
//	iss, err := fetcher.Issuer(ctx)
//	jws, errs, err := iss.VerifyAndValidate(tokenStr, &claims, v, time.Now())
package ajwt

import (
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
// use [Issuer.Verify] or [Issuer.UnsafeVerify] to authenticate the token and
// [JWS.UnmarshalClaims] to decode the payload into a typed struct.
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

// ClaimsValidator validates the standard JWT/OIDC claims in a token.
// Implemented by [*Validator] and [*MultiValidator].
type ClaimsValidator interface {
	Validate(claims StandardClaimsSource, now time.Time) ([]string, error)
}

// Decode parses a compact JWT string (header.payload.signature) into a JWS.
//
// It does not unmarshal the claims payload — call [JWS.UnmarshalClaims] after
// [Issuer.Verify] or [Issuer.UnsafeVerify] to populate a typed claims struct.
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
// [Issuer.Verify] or [Issuer.UnsafeVerify] before UnmarshalClaims to ensure
// the signature is authenticated before trusting the payload.
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

// Validator holds claim validation configuration for single-tenant use.
//
// Configure once at startup; pass to [Issuer.VerifyAndValidate] or call
// [Validator.Validate] directly per request.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type Validator struct {
	IgnoreIss      bool
	Iss            string
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

// Validate implements [ClaimsValidator].
func (v *Validator) Validate(claims StandardClaimsSource, now time.Time) ([]string, error) {
	return ValidateStandardClaims(claims.GetStandardClaims(), *v, now)
}

// MultiValidator holds claim validation configuration for multi-tenant use.
// Iss, Aud, and Azp accept slices — the claim value must appear in the slice.
type MultiValidator struct {
	Iss            []string
	IgnoreIss      bool
	IgnoreSub      bool
	Aud            []string
	IgnoreAud      bool
	IgnoreExp      bool
	IgnoreIat      bool
	IgnoreAuthTime bool
	MaxAge         time.Duration
	IgnoreNonce    bool
	IgnoreAmr      bool
	RequiredAmrs   []string
	IgnoreAzp      bool
	Azp            []string
	IgnoreJti      bool
}

// Validate implements [ClaimsValidator].
func (v *MultiValidator) Validate(claims StandardClaimsSource, now time.Time) ([]string, error) {
	sc := claims.GetStandardClaims()
	var errs []string

	if !v.IgnoreIss {
		if sc.Iss == "" {
			errs = append(errs, "missing or malformed 'iss' (token issuer)")
		} else if len(v.Iss) > 0 && !slices.Contains(v.Iss, sc.Iss) {
			errs = append(errs, fmt.Sprintf("'iss' %q not in allowed list", sc.Iss))
		}
	}

	if !v.IgnoreAud {
		if sc.Aud == "" {
			errs = append(errs, "missing or malformed 'aud' (audience)")
		} else if len(v.Aud) > 0 && !slices.Contains(v.Aud, sc.Aud) {
			errs = append(errs, fmt.Sprintf("'aud' %q not in allowed list", sc.Aud))
		}
	}

	if !v.IgnoreExp {
		if sc.Exp <= 0 {
			errs = append(errs, "missing or malformed 'exp' (expiration)")
		} else if sc.Exp < now.Unix() {
			duration := now.Sub(time.Unix(sc.Exp, 0))
			errs = append(errs, fmt.Sprintf("token expired %s ago", formatDuration(duration)))
		}
	}

	if !v.IgnoreIat {
		if sc.Iat <= 0 {
			errs = append(errs, "missing or malformed 'iat' (issued at)")
		} else if sc.Iat > now.Unix() {
			errs = append(errs, "'iat' is in the future")
		}
	}

	if v.MaxAge > 0 || !v.IgnoreAuthTime {
		if sc.AuthTime == 0 {
			errs = append(errs, "missing or malformed 'auth_time'")
		} else if sc.AuthTime > now.Unix() {
			errs = append(errs, "'auth_time' is in the future")
		} else if v.MaxAge > 0 {
			age := now.Sub(time.Unix(sc.AuthTime, 0))
			if age > v.MaxAge {
				errs = append(errs, fmt.Sprintf("'auth_time' exceeds max age %s by %s", formatDuration(v.MaxAge), formatDuration(age-v.MaxAge)))
			}
		}
	}

	if !v.IgnoreAmr {
		if len(sc.Amr) == 0 {
			errs = append(errs, "missing or malformed 'amr'")
		} else {
			for _, req := range v.RequiredAmrs {
				if !slices.Contains(sc.Amr, req) {
					errs = append(errs, fmt.Sprintf("missing required %q from 'amr'", req))
				}
			}
		}
	}

	if !v.IgnoreAzp {
		if len(v.Azp) > 0 && !slices.Contains(v.Azp, sc.Azp) {
			errs = append(errs, fmt.Sprintf("'azp' %q not in allowed list", sc.Azp))
		}
	}

	if len(errs) > 0 {
		return errs, fmt.Errorf("has errors")
	}
	return nil, nil
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
		} else if len(v.Iss) > 0 && claims.Iss != v.Iss {
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
		} else if len(v.Aud) > 0 && claims.Aud != v.Aud {
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

// Issuer holds public keys for a trusted token issuer.
//
// Issuer is immutable after construction — safe for concurrent use with no locking.
// Use [New] to construct with a fixed key set, or use [Signer.Issuer] or
// [JWKsFetcher.Issuer] to obtain one from a signer or remote JWKS endpoint.
type Issuer struct {
	pubKeys []PublicJWK
	keys    map[string]crypto.PublicKey // kid → key
}

// New creates an Issuer with an explicit set of public keys.
//
// The returned Issuer is immutable — keys cannot be added or removed after
// construction. For dynamic key rotation, see [JWKsFetcher].
func New(keys []PublicJWK) *Issuer {
	m := make(map[string]crypto.PublicKey, len(keys))
	for _, k := range keys {
		m[k.KID] = k.Key
	}
	return &Issuer{
		pubKeys: keys,
		keys:    m,
	}
}

// PublicKeys returns the public keys held by this Issuer.
func (iss *Issuer) PublicKeys() []PublicJWK {
	return iss.pubKeys
}

// ToJWKsJSON returns the Issuer's public keys as a [JWKsJSON] struct.
func (iss *Issuer) ToJWKsJSON() (JWKsJSON, error) {
	return ToJWKsJSON(iss.pubKeys)
}

// ToJWKs serializes the Issuer's public keys as a JWKS JSON document.
func (iss *Issuer) ToJWKs() ([]byte, error) {
	return ToJWKs(iss.pubKeys)
}

// Verify decodes tokenStr and verifies its signature.
//
// Returns (nil, err) on any failure — the caller never receives an
// unauthenticated JWS. For inspecting a JWS despite signature failure
// (e.g., for multi-issuer routing by kid/iss), use [Issuer.UnsafeVerify].
func (iss *Issuer) Verify(tokenStr string) (*JWS, error) {
	jws, err := iss.UnsafeVerify(tokenStr)
	if err != nil {
		return nil, err
	}
	return jws, nil
}

// UnsafeVerify decodes tokenStr and verifies the signature.
//
// Unlike [Issuer.Verify], UnsafeVerify returns the parsed [*JWS] even when
// signature verification fails — the error is non-nil but the JWS is
// available for inspection (e.g., to read the kid or iss for multi-issuer
// routing). Returns (nil, err) only when the token cannot be parsed at all.
//
// "Unsafe" means exp, aud, iss, and other claim values are NOT checked.
// Use [Issuer.VerifyAndValidate] for full validation.
func (iss *Issuer) UnsafeVerify(tokenStr string) (*JWS, error) {
	jws, err := Decode(tokenStr)
	if err != nil {
		return nil, err
	}

	if jws.Header.Kid == "" {
		return jws, fmt.Errorf("missing 'kid' header")
	}
	key, ok := iss.keys[jws.Header.Kid]
	if !ok {
		return jws, fmt.Errorf("unknown kid: %q", jws.Header.Kid)
	}

	signingInput := jws.Protected + "." + jws.Payload
	if err := verifyWith(signingInput, jws.Signature, jws.Header.Alg, key); err != nil {
		return jws, fmt.Errorf("signature verification failed: %w", err)
	}

	return jws, nil
}

// VerifyAndValidate verifies the token signature, unmarshals the claims
// into claims, and runs v.
//
// Returns a hard error (err != nil) for signature failures and decoding errors.
// Returns soft errors (errs != nil) for claim validation failures (wrong aud,
// expired token, etc.). If v is nil, claims are unmarshalled but not validated.
//
// claims must be a pointer whose underlying type embeds [StandardClaims]:
//
//	var claims AppClaims
//	jws, errs, err := iss.VerifyAndValidate(tokenStr, &claims, v, time.Now())
func (iss *Issuer) VerifyAndValidate(tokenStr string, claims StandardClaimsSource, v ClaimsValidator, now time.Time) (*JWS, []string, error) {
	jws, err := iss.Verify(tokenStr)
	if err != nil {
		return nil, nil, err
	}

	if err := jws.UnmarshalClaims(claims); err != nil {
		return nil, nil, err
	}

	if v == nil {
		return jws, nil, nil
	}

	errs, _ := v.Validate(claims, now) // discard sentinel; callers check len(errs) > 0
	return jws, errs, nil
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
