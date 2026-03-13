// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package jwt is a lightweight JWT/JWS/JWK library designed from first principles.
//
// # Use cases
//
// You are either an issuer (you sign tokens) or a relying party (you only verify
// them). As a relying party you either hold known public keys at startup, or you
// fetch them at runtime from a canonical JWKS endpoint.
//
//   - Issuer: use [NewSigner] → [Signer.Sign]; expose public keys via [Signer.ToJWKs]
//     or hand them directly to [New] for a co-located verifier.
//   - Relying party, known keys: use [New] with a []jwk.Key slice.
//   - Relying party, remote keys: use [KeyFetcher]; it fetches lazily and caches.
//
// # Design choices
//
// You'll almost never need a custom JOSE header. The algorithm is inferred
// automatically from the key type; KID comes from [PrivateKey.KID]; typ is
// always "JWT". [StandardJWS.Sign] handles all of this — you do not configure alg.
//
// You'll almost always need custom claims. [StandardJWS.UnmarshalClaims] accepts any
// pointer — no interface to implement for decoding. Embed [StandardClaims] in
// your struct to get the registered fields and satisfy [Claims] for free via
// Go method promotion, with zero boilerplate.
//
// Your custom claims validation logic is your own. [Verifier.VerifyJWT] authenticates the
// signature; [StandardJWS.UnmarshalClaims] decodes the payload; [Validator.Validate]
// checks the registered claim values (iss, aud, exp, etc.). These are three
// separate calls — you compose them in whatever order your application needs.
//
// [Decode] always succeeds for a well-formed token — inspect the header (kid,
// alg) before calling [Verifier.Verify] for multi-issuer routing.
//
// Convenience is not convenient if it gets in your way. This is a library, not
// a framework: it gives you composable pieces you call and control, not
// scaffolding you must conform to.
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

// JWS is the interface implemented by [*StandardJWS] and any custom JWS type.
//
// Custom implementations can embed [StandardHeader] to satisfy
// [JWS.GetStandardHeader] for free via Go method promotion — similar to
// how embedding [StandardClaims] satisfies [Claims].
//
// Use [Verifier.VerifyJWT] to get a [*StandardJWS] with access to
// [StandardJWS.UnmarshalClaims], or [Decode] + [Verifier.Verify] for
// routing by header fields before verifying the signature.
type JWS interface {
	GetProtected() []byte
	GetPayload() []byte
	GetSignature() []byte
	GetStandardHeader() *StandardHeader
	StandardClaims() (StandardClaims, error)
}

// StandardJWS is a decoded JSON Web Signature / JWT.
//
// It holds only the parsed structure — header, raw base64url fields, and
// decoded signature bytes. It carries no Claims interface and no Verified flag;
// use [Verifier.VerifyJWT] or [Decode]+[Verifier.Verify] to authenticate the token
// and [StandardJWS.UnmarshalClaims] to decode the payload into a typed struct.
//
// *StandardJWS implements [JWS].
type StandardJWS struct {
	protected []byte // base64url-encoded header
	header    StandardHeader
	payload   []byte // base64url-encoded claims
	signature []byte
}

// GetProtected returns the base64url-encoded protected header.
func (jws *StandardJWS) GetProtected() []byte { return jws.protected }

// GetPayload returns the base64url-encoded payload.
func (jws *StandardJWS) GetPayload() []byte { return jws.payload }

// GetSignature returns the decoded signature bytes.
func (jws *StandardJWS) GetSignature() []byte { return jws.signature }

// GetStandardHeader returns the decoded JOSE header fields.
// Implements [JWS].
func (jws *StandardJWS) GetStandardHeader() *StandardHeader { return &jws.header }

// StandardClaims decodes the payload and returns the standard JWT claims.
//
// It does not verify the signature — always call [Verifier.VerifyJWT] or
// [Decode]+[Verifier.Verify] before trusting the returned claims.
func (jws *StandardJWS) StandardClaims() (StandardClaims, error) {
	payload, err := base64.RawURLEncoding.DecodeString(string(jws.payload))
	if err != nil {
		return StandardClaims{}, fmt.Errorf("decode payload: %w", err)
	}
	var claims StandardClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		return StandardClaims{}, fmt.Errorf("unmarshal standard claims: %w", err)
	}
	return claims, nil
}

// StandardHeader holds the standard JOSE header fields.
//
// Embed StandardHeader in a custom JWS struct to satisfy [JWS.GetStandardHeader]
// for free via Go method promotion — zero boilerplate:
//
//	type MyJWS struct {
//	    jwt.StandardHeader        // promotes GetStandardHeader()
//	    // other fields...
//	}
//	// MyJWS now satisfies GetStandardHeader automatically.
type StandardHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	Typ string `json:"typ"`
}

// GetStandardHeader implements [JWS].
// Any struct embedding StandardHeader gets this method for free via promotion.
func (h *StandardHeader) GetStandardHeader() *StandardHeader { return h }

// Audience exists as a workaround for a quirk in the specification of the
// JWT "aud" claim: RFC 7519 §4.1.3 allows "aud" to be either a plain string
// or an array of strings, making it impossible to represent with a simple Go type.
//
// It unmarshals from both a single string ("foo") and an array of strings
// (["foo","bar"]). It marshals to a plain string for a single value and to
// an array for multiple values.
//
// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
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
// or as a JSON array for multiple values.
func (a Audience) MarshalJSON() ([]byte, error) {
	if len(a) == 1 {
		return json.Marshal(a[0])
	}
	return json.Marshal([]string(a))
}

// StandardClaims holds the registered JWT claim names defined in RFC 7519
// and extended by OpenID Connect Core.
//
// https://www.rfc-editor.org/rfc/rfc7519.html
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
	AMR      []string `json:"amr"`
	Azp      string   `json:"azp,omitempty"`
	JTI      string   `json:"jti"`
}

// GetStandardClaims implements [Claims].
// Any struct embedding StandardClaims gets this method for free via promotion.
func (sc *StandardClaims) GetStandardClaims() *StandardClaims { return sc }

// Claims is implemented for free by any struct that embeds [StandardClaims].
//
//	type AppClaims struct {
//	    jwt.StandardClaims        // promotes GetStandardClaims() — zero boilerplate
//	    Email string `json:"email"`
//	}
type Claims interface {
	GetStandardClaims() *StandardClaims
}

// Decode parses a compact JWT string (header.payload.signature) into a StandardJWS.
//
// It does not unmarshal the claims payload — call [StandardJWS.UnmarshalClaims] after
// [Verifier.VerifyJWT] or [Verifier.Verify] to populate a typed claims struct.
func Decode(tokenStr string) (*StandardJWS, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	var jws StandardJWS
	jws.protected, jws.payload = []byte(parts[0]), []byte(parts[1])

	header, err := base64.RawURLEncoding.DecodeString(string(jws.protected))
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %v", err)
	}
	if err := json.Unmarshal(header, &jws.header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %v", err)
	}

	jws.signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %v", err)
	}

	return &jws, nil
}

// UnmarshalClaims decodes the JWT payload into v.
//
// v must be a pointer to a struct (e.g. *AppClaims). Always call
// [Verifier.VerifyJWT] or [Decode]+[Verifier.Verify] before UnmarshalClaims to ensure
// the signature is authenticated before trusting the payload.
func (jws *StandardJWS) UnmarshalClaims(v any) error {
	payload, err := base64.RawURLEncoding.DecodeString(string(jws.payload))
	if err != nil {
		return fmt.Errorf("invalid claims encoding: %v", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("invalid claims JSON: %v", err)
	}
	return nil
}

// NewJWS creates an unsigned StandardJWS from the provided claims.
//
// The "alg" and "kid" header fields are set automatically by [StandardJWS.Sign]
// based on the key type and [PrivateKey.KID]. Call [StandardJWS.Encode] to
// produce the compact JWT string after signing.
func NewJWS(claims Claims) (*StandardJWS, error) {
	var jws StandardJWS

	jws.header = StandardHeader{
		// Alg and KID are set by Sign from the key type and PrivateKey.KID.
		Typ: "JWT",
	}
	headerJSON, err := json.Marshal(jws.header)
	if err != nil {
		return nil, fmt.Errorf("marshal header: %w", err)
	}
	jws.protected = []byte(base64.RawURLEncoding.EncodeToString(headerJSON))

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}
	jws.payload = []byte(base64.RawURLEncoding.EncodeToString(claimsJSON))

	return &jws, nil
}

// Sign signs the JWS in-place using pk.
//
// The KID is taken from pk.KID: if jws.Header.KID is empty it is set
// automatically; if it is already set to a different value, Sign returns an error.
//
// If jws.Header.Alg is already set to a value that is incompatible with the
// key type, Sign returns an error.
//
// Supported algorithms (inferred from key type):
//   - *ecdsa.PrivateKey P-256  → ES256 (SHA-256, raw r||s)
//   - *ecdsa.PrivateKey P-384  → ES384 (SHA-384, raw r||s)
//   - *ecdsa.PrivateKey P-521  → ES512 (SHA-512, raw r||s)
//   - *rsa.PrivateKey           → RS256 (PKCS#1 v1.5 + SHA-256)
//   - ed25519.PrivateKey         → EdDSA (Ed25519, RFC 8037)
//     https://www.rfc-editor.org/rfc/rfc8037.html
func (jws *StandardJWS) Sign(pk *PrivateKey) ([]byte, error) {
	switch {
	case jws.header.KID == "":
		jws.header.KID = pk.KID
	case jws.header.KID != pk.KID:
		return nil, fmt.Errorf("Sign: header kid %q conflicts with PrivateKey KID %q", jws.header.KID, pk.KID)
	}

	switch pub := pk.Signer.Public().(type) {
	case *ecdsa.PublicKey:
		alg, h, err := algForECKey(pub)
		if err != nil {
			return nil, err
		}
		if jws.header.Alg != "" && jws.header.Alg != alg {
			return nil, fmt.Errorf("Sign: key alg %s incompatible with header alg %q", alg, jws.header.Alg)
		}
		jws.header.Alg = alg
		headerJSON, err := json.Marshal(jws.header)
		if err != nil {
			return nil, fmt.Errorf("marshal header: %w", err)
		}
		jws.protected = []byte(base64.RawURLEncoding.EncodeToString(headerJSON))

		digest, err := digestFor(h, jws.signingInput())
		if err != nil {
			return nil, err
		}
		// crypto.Signer returns ASN.1 DER for ECDSA; convert to raw r||s for JWS.
		derSig, err := pk.Signer.Sign(rand.Reader, digest, h)
		if err != nil {
			return nil, fmt.Errorf("Sign %s: %w", alg, err)
		}
		jws.signature, err = ecdsaDERToRaw(derSig, pub.Curve)
		return jws.signature, err

	case *rsa.PublicKey:
		if jws.header.Alg != "" && jws.header.Alg != "RS256" {
			return nil, fmt.Errorf("Sign: RSA key incompatible with header alg %q (expected RS256)", jws.header.Alg)
		}
		jws.header.Alg = "RS256"
		headerJSON, err := json.Marshal(jws.header)
		if err != nil {
			return nil, fmt.Errorf("marshal header: %w", err)
		}
		jws.protected = []byte(base64.RawURLEncoding.EncodeToString(headerJSON))

		digest, err := digestFor(crypto.SHA256, jws.signingInput())
		if err != nil {
			return nil, err
		}
		// crypto.Signer returns raw PKCS#1 v1.5 bytes for RSA; use directly.
		jws.signature, err = pk.Signer.Sign(rand.Reader, digest, crypto.SHA256)
		return jws.signature, err

	case ed25519.PublicKey:
		if jws.header.Alg != "" && jws.header.Alg != "EdDSA" {
			return nil, fmt.Errorf("Sign: Ed25519 key incompatible with header alg %q (expected EdDSA)", jws.header.Alg)
		}
		jws.header.Alg = "EdDSA"
		headerJSON, err := json.Marshal(jws.header)
		if err != nil {
			return nil, fmt.Errorf("marshal header: %w", err)
		}
		jws.protected = []byte(base64.RawURLEncoding.EncodeToString(headerJSON))

		// Ed25519 signs the raw message with no pre-hashing; pass crypto.Hash(0).
		jws.signature, err = pk.Signer.Sign(rand.Reader, jws.signingInput(), crypto.Hash(0))
		return jws.signature, err

	default:
		return nil, fmt.Errorf(
			"Sign: unsupported public key type %T (supported: *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey)",
			pk.Signer.Public(),
		)
	}
}

// Encode produces the compact JWT string (header.payload.signature).
func (jws *StandardJWS) Encode() string {
	sig := base64.RawURLEncoding.EncodeToString(jws.signature)
	out := make([]byte, 0, len(jws.protected)+1+len(jws.payload)+1+len(sig))
	out = append(out, jws.protected...)
	out = append(out, '.')
	out = append(out, jws.payload...)
	out = append(out, '.')
	out = append(out, sig...)
	return string(out)
}

// signingInput builds the protected.payload byte slice used as the signing input.
func (jws *StandardJWS) signingInput() []byte {
	out := make([]byte, 0, len(jws.protected)+1+len(jws.payload))
	out = append(out, jws.protected...)
	out = append(out, '.')
	out = append(out, jws.payload...)
	return out
}

// DefaultMaxClockSkew is the tolerance applied to exp, iat, and auth_time checks
// when Validator.MaxClockSkew is zero. It covers common sub-second clock drift
// between distributed systems.
const DefaultMaxClockSkew = 5 * time.Second

// Validator holds claim validation configuration.
//
// Configure once at startup and reuse across requests. Iss, Aud, and Azp are
// slices — the claim value must appear in the configured list if the list is
// non-empty. Sub and JTI are presence-only checks: if not ignored, the claim
// must be non-empty, but its value is not matched (those are per-token and
// per-user; value matching must be done by the application).
//
// MaxClockSkew is applied to exp, iat, and auth_time to tolerate minor clock
// differences between systems. If zero, [DefaultMaxClockSkew] (5s) is used.
// Set to a negative value (e.g. -1) to disable skew tolerance entirely.
//
// Call [Validator.Validate] to check all standard fields.
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
	IgnoreJTI      bool          // if false, jti must be present (non-empty)
	IgnoreAuthTime bool
	MaxClockSkew      time.Duration // tolerance for exp/iat/auth_time; 0 = DefaultMaxClockSkew (5s); negative = no tolerance
	MaxAge         time.Duration
	IgnoreNonce    bool
	Nonce          string        // if set, token's nonce must match exactly
	IgnoreAMR      bool
	RequiredAMRs   []string // all of these must appear in the token's amr list
	MinAMRCount    int      // token's amr must have at least this many values; 0 = no minimum
	IgnoreAzp      bool
	Azp            []string      // token's azp must appear in list (if set)
}

// Validate checks the standard JWT/OIDC claims and returns soft errors.
func (v *Validator) Validate(claims Claims, now time.Time) ([]string, error) {
	return validateClaims(*claims.GetStandardClaims(), *v, now)
}

func validateClaims(claims StandardClaims, v Validator, now time.Time) ([]string, error) {
	var errs []string

	skew := v.MaxClockSkew
	if skew == 0 {
		skew = DefaultMaxClockSkew
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

	if !v.IgnoreJTI && claims.JTI == "" {
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

	if !v.IgnoreAMR {
		if len(claims.AMR) == 0 {
			errs = append(errs, "missing or malformed 'amr' (authorization methods, as json list)")
		} else {
			for _, required := range v.RequiredAMRs {
				if !slices.Contains(claims.AMR, required) {
					errs = append(errs, fmt.Sprintf("missing required '%s' from 'amr'", required))
				}
			}
			if v.MinAMRCount > 0 && len(claims.AMR) < v.MinAMRCount {
				errs = append(errs, fmt.Sprintf("'amr' has %d factor(s), need at least %d", len(claims.AMR), v.MinAMRCount))
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

// ToJWKsJSON returns the Verifier's public keys as a [jwk.KeySetJSON] struct.
func (iss *Verifier) ToJWKsJSON() (jwk.KeySetJSON, error) {
	return jwk.EncodeSet(iss.pubKeys)
}

// ToJWKs serializes the Verifier's public keys as a JWKS JSON document.
func (iss *Verifier) ToJWKs() ([]byte, error) {
	return jwk.Marshal(iss.pubKeys)
}

// Verify checks the signature of an already-decoded [JWS].
//
// Returns nil on success, a descriptive error on failure. Claim values
// (iss, aud, exp, etc.) are NOT checked — call [Validator.Validate] on the
// unmarshalled claims after verifying.
//
// Use [Decode] followed by Verify when you need to inspect the header
// (kid, alg) before deciding which verifier to apply:
//
//	jws, err := jwt.Decode(tokenStr)
//	if err != nil { /* malformed */ }
//	// route by kid before verifying
//	if err := chosenVerifier.Verify(jws); err != nil { /* bad sig */ }
//
// Use [Verifier.VerifyJWT] to decode and verify in one step.
func (iss *Verifier) Verify(jws JWS) error {
	h := jws.GetStandardHeader()
	if h.KID == "" {
		return fmt.Errorf("missing 'kid' header")
	}
	key, ok := iss.keys[h.KID]
	if !ok {
		return fmt.Errorf("unknown kid: %q", h.KID)
	}

	protected, payload := jws.GetProtected(), jws.GetPayload()
	signingInput := make([]byte, 0, len(protected)+1+len(payload))
	signingInput = append(signingInput, protected...)
	signingInput = append(signingInput, '.')
	signingInput = append(signingInput, payload...)
	if err := verifyWith(signingInput, jws.GetSignature(), h.Alg, key); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}
	return nil
}

// VerifyJWT decodes tokenStr and verifies its signature, returning the parsed
// [*StandardJWS] on success.
//
// Returns (nil, err) on any failure — the caller never receives an
// unauthenticated StandardJWS. Claim values (iss, aud, exp, etc.) are NOT checked;
// call [Validator.Validate] on the unmarshalled claims after VerifyJWT:
//
//	jws, err := iss.VerifyJWT(tokenStr)
//	if err != nil { /* bad sig, malformed token, unknown kid */ }
//	var claims AppClaims
//	if err := jws.UnmarshalClaims(&claims); err != nil { /* ... */ }
//	errs, _ := v.Validate(&claims, time.Now())
//
// For routing by kid/iss before verifying, use [Decode] then [Verifier.Verify].
func (iss *Verifier) VerifyJWT(tokenStr string) (*StandardJWS, error) {
	jws, err := Decode(tokenStr)
	if err != nil {
		return nil, err
	}
	if err := iss.Verify(jws); err != nil {
		return nil, err
	}
	return jws, nil
}

// verifyWith checks a JWS signature using the given algorithm and public key.
// Returns nil on success, a descriptive error on failure.
func verifyWith(signingInput []byte, sig []byte, alg string, key jwk.PublicKey) error {
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
		if !ed25519.Verify(k, signingInput, sig) {
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

func digestFor(h crypto.Hash, data []byte) ([]byte, error) {
	switch h {
	case crypto.SHA256:
		d := sha256.Sum256(data)
		return d[:], nil
	case crypto.SHA384:
		d := sha512.Sum384(data)
		return d[:], nil
	case crypto.SHA512:
		d := sha512.Sum512(data)
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
