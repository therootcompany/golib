// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package jwt is a lightweight JWT/JWS/JWK library designed from first
// principles:
//
//   - [Verifier] is immutable — constructed with a fixed key set, safe for concurrent use.
//   - [Signer] manages private keys and returns [*Verifier] for verification.
//   - [KeyFetcher] lazily fetches and caches JWKS keys, returning a fresh [*Verifier] on demand.
//   - [Validator] validates standard JWT/OIDC claims.
//   - [JWS] is a parsed structure — use [Verifier.Verify] or [Verifier.UnsafeVerify] to authenticate.
//   - [JWS.UnmarshalClaims] accepts any type — no Claims interface to implement.
//   - [Claims] is satisfied for free by embedding [StandardClaims].
//
// Typical usage with VerifyAndValidate:
//
//	// At startup:
//	signer, err := jwt.NewSigner([]jwt.PrivateKey{{Signer: privKey}})
//	iss := signer.Verifier()
//	v := &jwt.Validator{Iss: []string{"https://example.com"}, Aud: []string{"my-app"}}
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
//	iss := jwt.New(keys)
//	jws, err := iss.UnsafeVerify(tokenStr)
//	var claims AppClaims
//	jws.UnmarshalClaims(&claims)
//	errs, err := jwt.ValidateStandardClaims(claims.StandardClaims,
//	    jwt.Validator{Aud: []string{"myapp"}}, time.Now())
//
// Typical usage with KeyFetcher (dynamic keys from remote):
//
//	fetcher := &jwt.KeyFetcher{
//	    URL:         "https://accounts.example.com/.well-known/jwks.json",
//	    MaxAge:      time.Hour,
//	    StaleAge:    time.Hour,
//	    KeepOnError: true,
//	}
//	iss, err := fetcher.Verifier(ctx)
//	jws, errs, err := iss.VerifyAndValidate(tokenStr, &claims, v, time.Now())
package jwt

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

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// JWS is a decoded JSON Web Signature / JWT.
//
// It holds only the parsed structure — header, raw base64url fields, and
// decoded signature bytes. It carries no Claims interface and no Verified flag;
// use [Verifier.Verify] or [Verifier.UnsafeVerify] to authenticate the token and
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

// Audience represents the "aud" JWT claim (RFC 7519 §4.1.3).
//
// It unmarshals from both a single string ("foo") and an array of strings
// (["foo","bar"]). It marshals to a plain string for a single value and to
// an array for multiple values, per the RFC.
type Audience []string

// Contains reports whether s appears in the audience list.
func (a Audience) Contains(s string) bool {
	return slices.Contains([]string(a), s)
}

// UnmarshalJSON decodes both the string and []string forms of the "aud" claim.
func (a *Audience) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		*a = Audience{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return fmt.Errorf("'aud' must be a string or array of strings: %w", err)
	}
	*a = ss
	return nil
}

// MarshalJSON encodes the audience as a plain string when there is one value,
// or as a JSON array for multiple values, per RFC 7519 §4.1.3.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// StandardClaims holds the registered JWT claim names defined in RFC 7519
// and extended by OpenID Connect Core.
//
// Embed StandardClaims in your own claims struct to satisfy [Claims]
// for free via Go's method promotion — zero boilerplate:
//
//	type AppClaims struct {
//	    jwt.StandardClaims        // promotes GetStandardClaims()
//	    Email string `json:"email"`
//	    Roles []string `json:"roles"`
//	}
//	// AppClaims now satisfies Claims automatically.
type StandardClaims struct {
	Iss      string   `json:"iss"`
	Sub      string   `json:"sub"`
	Aud      Audience `json:"aud,omitempty"`
	Exp      int64    `json:"exp"`
	Iat      int64    `json:"iat"`
	AuthTime int64    `json:"auth_time"`
	Nonce    string   `json:"nonce,omitempty"`
	Amr      []string `json:"amr"`
	Azp      string   `json:"azp,omitempty"`
	Jti      string   `json:"jti"`
}

// GetStandardClaims implements [Claims].
// Any struct embedding StandardClaims gets this method for free via promotion.
func (sc StandardClaims) GetStandardClaims() StandardClaims { return sc }

// Claims is implemented for free by any struct that embeds [StandardClaims].
//
//	type AppClaims struct {
//	    jwt.StandardClaims        // promotes GetStandardClaims() — zero boilerplate
//	    Email string `json:"email"`
//	}
type Claims interface {
	GetStandardClaims() StandardClaims
}

// ClaimsValidator validates the standard JWT/OIDC claims in a token.
// Implemented by [*Validator].
type ClaimsValidator interface {
	Validate(claims Claims, now time.Time) ([]string, error)
}

// Decode parses a compact JWT string (header.payload.signature) into a JWS.
//
// It does not unmarshal the claims payload — call [JWS.UnmarshalClaims] after
// [Verifier.Verify] or [Verifier.UnsafeVerify] to populate a typed claims struct.
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
// [Verifier.Verify] or [Verifier.UnsafeVerify] before UnmarshalClaims to ensure
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
// kid identifies the signing key; pass "" when using [JWS.Sign] with a
// [*PrivateKey], which sets the KID automatically from the key. The "alg"
// header field is always set when [JWS.Sign] is called. Call [JWS.Encode]
// to produce the compact JWT string after signing.
func NewJWSFromClaims(claims any, kid string) (*JWS, error) {
	var jws JWS

	jws.Header = StandardHeader{
		// Alg is set by Sign based on the key type.
		Kid: kid,
		Typ: "JWT",
	}
	headerJSON, err := json.Marshal(jws.Header)
	if err != nil {
		return nil, fmt.Errorf("marshal header: %w", err)
	}
	jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}
	jws.Payload = base64.RawURLEncoding.EncodeToString(claimsJSON)

	return &jws, nil
}

// Sign signs the JWS in-place using the provided [crypto.Signer].
//
// If key is a [*PrivateKey], the KID is taken from it: if jws.Header.Kid is
// empty it is set automatically; if it is already set to a different value,
// Sign returns an error.
//
// If jws.Header.Alg is already set to a value that is incompatible with the
// provided key type, Sign returns an error.
//
// Supported algorithms (inferred from key type):
//   - *ecdsa.PublicKey P-256  → ES256 (SHA-256, raw r||s)
//   - *ecdsa.PublicKey P-384  → ES384 (SHA-384, raw r||s)
//   - *ecdsa.PublicKey P-521  → ES512 (SHA-512, raw r||s)
//   - *rsa.PublicKey           → RS256 (PKCS#1 v1.5 + SHA-256)
//   - ed25519.PublicKey         → EdDSA (Ed25519, RFC 8037)
func (jws *JWS) Sign(key crypto.Signer) ([]byte, error) {
	// If the signer is a *PrivateKey, apply its KID to the header.
	if pk, ok := key.(*PrivateKey); ok {
		switch {
		case jws.Header.Kid == "":
			jws.Header.Kid = pk.KID
		case jws.Header.Kid != pk.KID:
			return nil, fmt.Errorf("Sign: header kid %q conflicts with PrivateKey KID %q", jws.Header.Kid, pk.KID)
		}
	}

	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		alg, h, err := algForECKey(pub)
		if err != nil {
			return nil, err
		}
		if jws.Header.Alg != "" && jws.Header.Alg != alg {
			return nil, fmt.Errorf("Sign: key alg %s incompatible with header alg %q", alg, jws.Header.Alg)
		}
		jws.Header.Alg = alg
		headerJSON, err := json.Marshal(jws.Header)
		if err != nil {
			return nil, fmt.Errorf("marshal header: %w", err)
		}
		jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

		digest, err := digestFor(h, jws.Protected+"."+jws.Payload)
		if err != nil {
			return nil, err
		}
		// crypto.Signer returns ASN.1 DER for ECDSA; convert to raw r||s for JWS.
		derSig, err := key.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, fmt.Errorf("Sign %s: %w", alg, err)
		}
		jws.Signature, err = ecdsaDERToRaw(derSig, pub.Curve)
		return jws.Signature, err

	case *rsa.PublicKey:
		if jws.Header.Alg != "" && jws.Header.Alg != "RS256" {
			return nil, fmt.Errorf("Sign: RSA key incompatible with header alg %q (expected RS256)", jws.Header.Alg)
		}
		jws.Header.Alg = "RS256"
		headerJSON, err := json.Marshal(jws.Header)
		if err != nil {
			return nil, fmt.Errorf("marshal header: %w", err)
		}
		jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

		digest, err := digestFor(crypto.SHA256, jws.Protected+"."+jws.Payload)
		if err != nil {
			return nil, err
		}
		// crypto.Signer returns raw PKCS#1 v1.5 bytes for RSA; use directly.
		jws.Signature, err = key.Sign(rand.Reader, digest, crypto.SHA256)
		return jws.Signature, err

	case ed25519.PublicKey:
		if jws.Header.Alg != "" && jws.Header.Alg != "EdDSA" {
			return nil, fmt.Errorf("Sign: Ed25519 key incompatible with header alg %q (expected EdDSA)", jws.Header.Alg)
		}
		jws.Header.Alg = "EdDSA"
		headerJSON, err := json.Marshal(jws.Header)
		if err != nil {
			return nil, fmt.Errorf("marshal header: %w", err)
		}
		jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

		// Ed25519 signs the raw message with no pre-hashing; pass crypto.Hash(0).
		signingInput := jws.Protected + "." + jws.Payload
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

// DefaultClockSkew is the tolerance applied to exp, iat, and auth_time checks
// when Validator.ClockSkew is zero. It covers common sub-second clock drift
// between distributed systems.
const DefaultClockSkew = 5 * time.Second

// Validator holds claim validation configuration.
//
// Configure once at startup and reuse across requests. Iss, Aud, and Azp are
// slices — the claim value must appear in the configured list if the list is
// non-empty. Sub and Jti are presence-only checks: if not ignored, the claim
// must be non-empty, but its value is not matched (those are per-token and
// per-user; value matching must be done by the application).
//
// ClockSkew is applied to exp, iat, and auth_time to tolerate minor clock
// differences between systems. If zero, [DefaultClockSkew] (5s) is used.
// Set to a negative value (e.g. -1) to disable skew tolerance entirely.
//
// Pass to [Verifier.VerifyAndValidate] or call [Validator.Validate] directly.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type Validator struct {
	IgnoreIss      bool
	Iss            []string      // token's iss must appear in list (if set)
	IgnoreSub      bool          // if false, sub must be present (non-empty)
	IgnoreAud      bool
	Aud            []string      // token's aud must intersect list (if set)
	IgnoreExp      bool
	IgnoreIat      bool
	IgnoreJti      bool          // if false, jti must be present (non-empty)
	IgnoreAuthTime bool
	ClockSkew      time.Duration // tolerance for exp/iat/auth_time; 0 = DefaultClockSkew (5s); negative = no tolerance
	MaxAge         time.Duration
	IgnoreNonce    bool
	Nonce          string        // if set, token's nonce must match exactly
	IgnoreAmr      bool
	RequiredAmrs   []string
	IgnoreAzp      bool
	Azp            []string      // token's azp must appear in list (if set)
}

// Validate implements [ClaimsValidator].
func (v *Validator) Validate(claims Claims, now time.Time) ([]string, error) {
	return ValidateStandardClaims(claims.GetStandardClaims(), *v, now)
}

// ValidateStandardClaims checks the registered JWT/OIDC claim fields against v.
//
// Exported so callers can use it directly without a [Validator] receiver:
//
//	errs, err := jwt.ValidateStandardClaims(claims.StandardClaims, v, time.Now())
func ValidateStandardClaims(claims StandardClaims, v Validator, now time.Time) ([]string, error) {
	var errs []string

	skew := v.ClockSkew
	if skew == 0 {
		skew = DefaultClockSkew
	} else if skew < 0 {
		skew = 0
	}

	if !v.IgnoreIss {
		if claims.Iss == "" {
			errs = append(errs, "missing or malformed 'iss' (token issuer)")
		} else if len(v.Iss) > 0 && !slices.Contains(v.Iss, claims.Iss) {
			errs = append(errs, fmt.Sprintf("'iss' %q not in allowed list", claims.Iss))
		}
	}

	if !v.IgnoreSub && claims.Sub == "" {
		errs = append(errs, "missing or malformed 'sub' (subject, typically pairwise user id)")
	}

	if !v.IgnoreAud {
		if len(claims.Aud) == 0 {
			errs = append(errs, "missing or malformed 'aud' (audience receiving token)")
		} else if len(v.Aud) > 0 && !slices.ContainsFunc([]string(claims.Aud), func(a string) bool {
			return slices.Contains(v.Aud, a)
		}) {
			errs = append(errs, fmt.Sprintf("'aud' not in allowed list: %v", claims.Aud))
		}
	}

	if !v.IgnoreExp {
		if claims.Exp <= 0 {
			errs = append(errs, "missing or malformed 'exp' (expiration date in seconds)")
		} else if now.After(time.Unix(claims.Exp, 0).Add(skew)) {
			duration := now.Sub(time.Unix(claims.Exp, 0))
			expTime := time.Unix(claims.Exp, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("token expired %s ago (%s)", formatDuration(duration), expTime))
		}
	}

	if !v.IgnoreIat {
		if claims.Iat <= 0 {
			errs = append(errs, "missing or malformed 'iat' (issued at, when token was signed)")
		} else if time.Unix(claims.Iat, 0).After(now.Add(skew)) {
			duration := time.Unix(claims.Iat, 0).Sub(now)
			iatTime := time.Unix(claims.Iat, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("'iat' (issued at) is %s in the future (%s)", formatDuration(duration), iatTime))
		}
	}

	if !v.IgnoreJti && claims.Jti == "" {
		errs = append(errs, "missing or malformed 'jti' (JWT ID)")
	}

	if !v.IgnoreAuthTime {
		if claims.AuthTime == 0 {
			errs = append(errs, "missing or malformed 'auth_time' (time of real-world user authentication, in seconds)")
		} else {
			authTime := time.Unix(claims.AuthTime, 0)
			authTimeStr := authTime.Format("2006-01-02 15:04:05 MST")
			age := now.Sub(authTime)
			diff := age - v.MaxAge
			if authTime.After(now.Add(skew)) {
				fromNow := authTime.Sub(now)
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

	if !v.IgnoreNonce && len(v.Nonce) > 0 && v.Nonce != claims.Nonce {
		errs = append(errs, fmt.Sprintf("'nonce' mismatch: got %s, expected %s", claims.Nonce, v.Nonce))
	}

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

	if !v.IgnoreAzp && len(v.Azp) > 0 && !slices.Contains(v.Azp, claims.Azp) {
		errs = append(errs, fmt.Sprintf("'azp' %q not in allowed list", claims.Azp))
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

// Verifier holds the public keys of a JWT issuer and verifies token signatures.
//
// In OIDC terminology, the "issuer" is the identity provider that both signs
// tokens and publishes its public keys. Verifier represents that issuer from
// the relying party's perspective — you hold its public keys and use them to
// verify that tokens were legitimately signed by it.
//
// Verifier is immutable after construction — safe for concurrent use with no locking.
// Use [New] to construct with a fixed key set, or use [Signer.Verifier] or
// [KeyFetcher.Verifier] to obtain one from a signer or remote JWKS endpoint.
type Verifier struct {
	pubKeys []jwk.Key
	keys    map[string]jwk.PublicKey // kid → key
}

// New creates a Verifier with an explicit set of public keys.
//
// The returned Verifier is immutable — keys cannot be added or removed after
// construction. For dynamic key rotation, see [KeyFetcher].
func New(keys []jwk.Key) *Verifier {
	m := make(map[string]jwk.PublicKey, len(keys))
	for _, k := range keys {
		m[k.KID] = k.Key
	}
	return &Verifier{
		pubKeys: keys,
		keys:    m,
	}
}

// PublicKeys returns the public keys held by this Verifier.
func (iss *Verifier) PublicKeys() []jwk.Key {
	return iss.pubKeys
}

// ToJWKsJSON returns the Verifier's public keys as a [jwk.SetJSON] struct.
func (iss *Verifier) ToJWKsJSON() (jwk.SetJSON, error) {
	return jwk.EncodeSet(iss.pubKeys)
}

// ToJWKs serializes the Verifier's public keys as a JWKS JSON document.
func (iss *Verifier) ToJWKs() ([]byte, error) {
	return jwk.Marshal(iss.pubKeys)
}

// Verify decodes tokenStr and verifies its signature.
//
// Returns (nil, err) on any failure — the caller never receives an
// unauthenticated JWS. For inspecting a JWS despite signature failure
// (e.g., for multi-issuer routing by kid/iss), use [Verifier.UnsafeVerify].
func (iss *Verifier) Verify(tokenStr string) (*JWS, error) {
	jws, err := iss.UnsafeVerify(tokenStr)
	if err != nil {
		return nil, err
	}
	return jws, nil
}

// UnsafeVerify decodes tokenStr and verifies the signature.
//
// Unlike [Verifier.Verify], UnsafeVerify returns the parsed [*JWS] even when
// signature verification fails — the error is non-nil but the JWS is
// available for inspection (e.g., to read the kid or iss for multi-issuer
// routing). Returns (nil, err) only when the token cannot be parsed at all.
//
// "Unsafe" means exp, aud, iss, and other claim values are NOT checked.
// Use [Verifier.VerifyAndValidate] for full validation.
func (iss *Verifier) UnsafeVerify(tokenStr string) (*JWS, error) {
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
func (iss *Verifier) VerifyAndValidate(tokenStr string, claims Claims, v ClaimsValidator, now time.Time) (*JWS, []string, error) {
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
func verifyWith(signingInput string, sig []byte, alg string, key jwk.PublicKey) error {
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
		digest, err := digestFor(h, signingInput)
		if err != nil {
			return err
		}
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
		digest, err := digestFor(crypto.SHA256, signingInput)
		if err != nil {
			return err
		}
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

func digestFor(h crypto.Hash, data string) ([]byte, error) {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256([]byte(data))
		return d[:], nil
	case crypto.SHA384:
		d := sha512.Sum384([]byte(data))
		return d[:], nil
	case crypto.SHA512:
		d := sha512.Sum512([]byte(data))
		return d[:], nil
	default:
		return nil, fmt.Errorf("jwt: unsupported hash %v", h)
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
