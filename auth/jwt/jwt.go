// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package jwt is a lightweight library for the JWT/JWS/JWK parts of JOSE/OIDC/OAuth2 library, designed from first principles, built exclusively for modern Go (1.26 and up) and current standards (OIDC Core 1.0 errata set 2, OAuth 2.1 draft 15, MCP).
//
// High convenience. Low boilerplate. Easy to customize. Focused:
//
// - You're either building an Issuer (sign JWTs) or Relying Party (verifies and validates JWTs)
// - You're implementing part of JOSE, OIDC or OAuth2 and may have a /jwks.json endpoint
// - You almost never need a custom Header
// - You almost always need custom Claims (token Payload)
// - You want type-safe keys (but you don't want to have to type-switch on them)
// - You may also be implementing MCP support for Ai / Agents
// - You probably do a little of all sides
//
// This package implements So rather than implementing to the spec article by article, this implements by flow.
//
// This was created with Ai assistance to be able to iterate quickly over different design choices, but every line of the code has been manually reviewed for correctness, as well as many of the tests.
//
// # Use case: Issuer (+Relying Party)
//
// You're building the thing that has the Private Keys, signs the tokens + verifies tokens and validates claims.
//   - create a [NewSigner] with the private keys
//   - use json.Marshal(&signer.JWKs) to publish a /jwks.json endpoint ([Signer] embeds [jwk.JWKs])
//   - use [Signer.Sign] + [IDTokenClaims] or [StandardClaims] to create a JWT
//   - use [Signer.Verifier] to verify the JWT (bearer token)
//   - use [UnmarshalClaims] to get your user info
//   - use [Validator.Validate] to validate the claims (user info payload)
//   - use custom Validation for your own Claims type with a [Validator], or by hand - dealer's choice
//
// # Use case: Relying Party
//
// 2. Relying Party: you're building a thing that uses Public Keys to verify and validates tokens
//   - you may already know the public keys (and redeploy when they change)
//   - or you fetch them at runtime from a /jwks.json endpoint (and cache and update periodically)
//   - Relying party, known keys: use [New] with a []jwk.PublicKey slice.
//   - Relying party, remote keys: use [KeyFetcher]; it fetches lazily and caches.
//   - use [Verifier.Verify] to verify the JWT (bearer token)
//   - use [UnmarshalClaims] to get your user info
//   - use [Validator.Validate] to validate the claims (user info payload)
//   - use custom Validation for your own Claims type with a [Validator], or by hand - dealer's choice
//
// # Use case: MCP / Agents
//
// # Design choices
//
// Convenience is not convenient if it gets in your way. This is a library, not
// a framework: it gives you composable pieces you call and control, not
// scaffolding you must conform to.
//
//   - Sane defaults for everything, without hiding anything you may need to inspect.
//   - There should be one obvious right way to do it.
//   - Claims are the most important building-facing detail.
//   - Use simple type embedded for maximum convenience without sacrificing optionality.
//   - [StandardClaims] for typical user info, [IDTokenClaims] for minimal auth info.
//     (both satisfy [Claims] for free via Go method promotion)
//   - [UnmarshalClaims] to get your type-safe claims effortlessly.
//   - [IDTokenValidator] for typical, strict auth validation, [RFCValidator] for special use cases
//     (or bring your own, or ignore it and do it how you like)
//   - Header always always used in the standard way, and tightly coupled to signing and
//     verification - it stays fully and customizable as part of the JWS interfaces
//     (embedding [RawJWT] and [Header] make it easy to satisfy [VerifiableJWS] or [SignableJWS])
//   - Accessible error details (so that you don't have to round trip just to get the next one)
//
// Key takeaway: Your claims are your own. You can take what you get for free, or add what you need at no cost to you.
//
// # Security
//
// You don't need to be a crypto export to use this library - but if you are, hopefully
// you find it to be the best you've ever used.
//
// 1. YAGNI: Don't implement what you don't need = less surface area = greater security.
//
// The researchers who write specifications are notorious for imagining every
// hypothetical - which has resulted in numerous security flaws over the years.
// There's nothing in here that I haven't seen in the wild and found useful.
// And I'm happy to extend if needed.
//
// 2. Verify AND Validate
//
// As an Issuer (owner) you [Signer.Sign] and then [jwt.Encode].
//
// As a Relying Party (client) you [jwt.Decode], [Verifier.Verify] and [Validator.Validate].
//
// Why not a single step? Because Claims (sometimes called "User" in other libs) is the thing
// you actually care about, and actually want type safety for. After trying various approaches
// with embedding and generics, what I landed on is that the only ergonomic and type-safe way
// to Verify a JWT and Validate Claims is to have the two be separate operations.
//
// It's why you get to use this library as a library and how you get to have all of the
// convenience without sacrificing control and customization of the thing you're most likely
// to want to be able to customize (and debug).
//
// 3. Algorithms: The fewer the merrier.
//
// Only asymmetric (public-key) algorithms are implemented.
//
// You should use Ed25519. It's the end-game algorithm - all upside, no known
// downsides, and it's supported ubiquitously - Web Browsers, Node, Go, Rust,
// JavaScript, etc.
//
// Ed25519 is the default for this library.
// ECDSA is probably the most popular, so it's provided for backwards compatibility.
// RSA is only is provided for backwards compatibility - it's larger, slower, and no real benefit.
//
//   - EC P-256  => ES256 (ECDSA + SHA-256, RFC 7518 §3.4)
//   - EC P-384  => ES384 (ECDSA + SHA-384)
//   - EC P-521  => ES512 (ECDSA + SHA-512)
//   - RSA       => RS256 (PKCS#1 v1.5 + SHA-256, RFC 7518 §3.3)
//   - Ed25519   => EdDSA (RFC 8037)
//
// Supported algorithms are derived automatically from the key type - you never
// configure alg directly.
//
// The verification process selects a key by matching the "kid" (KeyID) of token
// and the key and then checking "alg" before any cryptographic operation is attempted.
// An alg/key-type mismatch is a hard error.
package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256 with crypto.Hash
	_ "crypto/sha512" // register SHA-384 and SHA-512 with crypto.Hash
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// JWS is the read-only interface implemented by [*JWS] and any custom
// JWS type. It exposes only the parsed header and payload - no mutation.
//
// Use [Verifier.VerifyJWT] to get a verified [*JWS], then call
// [UnmarshalClaims] to decode the payload. Or use [Decode] + [Verifier.Verify]
// for routing by header fields before verifying the signature.
type VerifiableJWS interface {
	GetProtected() []byte
	GetPayload() []byte
	GetSignature() []byte
	// GetHeader returns a copy of the decoded JOSE header fields.
	// Callers cannot mutate the JWS's internal header through the returned value.
	GetHeader() Header
}

// SignableJWS extends [VerifiableJWS] with the two hooks [Signer.SignJWS] needs.
// [*JWS] implements both [VerifiableJWS] and [SignableJWS].
//
// Custom JWS types implement MarshalHeader to merge the signer's standard
// fields (alg, kid, typ) with any custom header fields and return the
// encoded protected bytes. They implement SetSignature to store the result.
// No cryptographic knowledge is required - the [Signer] handles all of that.
type SignableJWS interface {
	VerifiableJWS
	// MarshalHeader encodes the full protected header by merging hdr into
	// the JWS's own header fields, stores the result internally, and returns
	// the base64url-encoded bytes used as the signing-input prefix.
	MarshalHeader(hdr Header) ([]byte, error)
	// SetSignature stores the computed signature bytes.
	SetSignature(sig []byte)
}

type RawJWT struct {
	protected []byte // base64url-encoded header
	payload   []byte // base64url-encoded claims
	signature []byte
}

// GetProtected implements [VerifiableJWS].
func (raw *RawJWT) GetProtected() []byte { return raw.protected }

// GetPayload implements [VerifiableJWS].
func (raw *RawJWT) GetPayload() []byte { return raw.payload }

// GetSignature implements [VerifiableJWS].
func (raw *RawJWT) GetSignature() []byte { return raw.signature }

// SetSignature implements [SignableJWS].
func (raw *RawJWT) SetSignature(sig []byte) { raw.signature = sig }

// JWS is a decoded JSON Web Signature / JWT.
//
// It holds only the parsed structure - header, raw base64url fields, and
// decoded signature bytes. It carries no Claims interface and no Verified flag;
// use [Verifier.VerifyJWT] or [Decode]+[Verifier.Verify] to authenticate the token
// and [UnmarshalClaims] to decode the payload into a typed struct.
//
// *JWS implements [VerifiableJWS].
type JWS struct {
	RawJWT
	header jwsHeader
}

// GetHeader returns a copy of the decoded JOSE header fields.
// Implements [VerifiableJWS]. The returned value is a copy - mutations do not affect the JWS.
func (jws *JWS) GetHeader() Header { return jws.header.Header }

// MarshalHeader encodes hdr as the protected header, stores it internally,
// and returns the base64url-encoded bytes. Implements [SignableJWS].
//
// Custom JWS types override this to merge hdr with their own additional
// header fields before encoding.
func (jws *JWS) MarshalHeader(hdr Header) ([]byte, error) {
	jws.header.Header = hdr
	data, err := json.Marshal(jws.header)
	if err != nil {
		return nil, fmt.Errorf("MarshalHeader: %w", err)
	}
	jws.protected = []byte(base64.RawURLEncoding.EncodeToString(data))
	return jws.protected, nil
}

// UnmarshalIDTokenClaims decodes the payload of jws into an [IDTokenClaims] struct.
//
// Always call [Verifier.VerifyJWT] or [Decode]+[Verifier.Verify] before
// UnmarshalIDTokenClaims - the signature must be authenticated before trusting
// the payload. Works with any [VerifiableJWS] implementation, not just [*JWS].
func UnmarshalIDTokenClaims(jws VerifiableJWS) (IDTokenClaims, error) {
	var claims IDTokenClaims
	return claims, UnmarshalClaims(jws, &claims)
}

// UnmarshalStandardClaims decodes the payload of jws into a [StandardClaims] struct.
//
// Always call [Verifier.VerifyJWT] or [Decode]+[Verifier.Verify] before
// UnmarshalStandardClaims - the signature must be authenticated before trusting
// the payload. Works with any [VerifiableJWS] implementation, not just [*JWS].
func UnmarshalStandardClaims(jws VerifiableJWS) (StandardClaims, error) {
	var claims StandardClaims
	return claims, UnmarshalClaims(jws, &claims)
}

// jwsHeader is an example of the pattern callers use when embedding Header in
// a custom JWS type. Embed Header, and all its fields are promoted through the
// struct. To implement a custom JWS type, copy this struct and replace Header
// embedding with whatever custom header fields you need.
type jwsHeader struct {
	Header
}

// Header holds the standard JOSE header fields used in the JOSE protected header.
type Header struct {
	Alg string `json:"alg"`
	KID string `json:"kid"`
	Typ string `json:"typ"`
}

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

// IDTokenClaims holds the OIDC Core §2 ID Token claims: the RFC 7519
// registered claim names (iss, sub, aud, exp, iat, jti) plus the
// OIDC-specific authentication event fields (auth_time, nonce, amr, azp).
//
// For OIDC UserInfo profile fields (name, email, phone, locale, etc.),
// use [StandardClaims] instead - it embeds IDTokenClaims and adds §5.1 fields.
//
// https://www.rfc-editor.org/rfc/rfc7519.html
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
//
// Embed IDTokenClaims or StandardClaims in your own claims struct to
// satisfy [Claims] for free via Go's method promotion - zero boilerplate:
//
//	type AppClaims struct {
//	    jwt.StandardClaims             // promotes GetIDTokenClaims()
//	    RoleList string `json:"roles"`
//	}
//	// AppClaims now satisfies Claims automatically.
type IDTokenClaims struct {
	// RFC 7519 §4.1 registered claims - all OPTIONAL per the RFC;
	// higher-level profiles (OIDC, RFC 9068) may require subsets.
	Iss string   `json:"iss"`
	Sub string   `json:"sub"`
	Aud Audience `json:"aud,omitempty"`
	Exp int64    `json:"exp"`
	NBF int64    `json:"nbf,omitempty"` // Not Before: reject token before this Unix time
	Iat int64    `json:"iat"`
	JTI string   `json:"jti,omitempty"` // JWT ID: unique identifier for replay prevention

	// OIDC Core §2 authentication event claims - all OPTIONAL per OIDC.
	AuthTime int64    `json:"auth_time,omitempty"` // REQUIRED when max_age requested
	Nonce    string   `json:"nonce,omitempty"`     // REQUIRED when sent in auth request
	AMR      []string `json:"amr,omitempty"`       // Authentication Methods References
	Azp      string   `json:"azp,omitempty"`       // Authorized party (rare; see OIDC §2)
}

// StandardClaims extends [IDTokenClaims] with the OIDC Core §5.1 UserInfo
// standard profile claims. Embed StandardClaims to get both the ID Token
// fields and the user profile fields with zero boilerplate.
//
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
//
//	type AppClaims struct {
//	    jwt.StandardClaims       // promotes GetIDTokenClaims()
//	    Roles []string `json:"roles"`
//	}
type StandardClaims struct {
	IDTokenClaims

	// Profile fields (OIDC Core §5.1)
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Profile           string `json:"profile,omitempty"` // URL of end-user's profile page
	Picture           string `json:"picture,omitempty"` // URL of end-user's profile picture
	Website           string `json:"website,omitempty"` // URL of end-user's web page

	// Contact fields
	Email               string `json:"email,omitempty"`
	EmailVerified       bool   `json:"email_verified,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"`
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`

	// Locale / time fields
	Gender    string `json:"gender,omitempty"`
	Birthdate string `json:"birthdate,omitempty"` // YYYY, YYYY-MM, or YYYY-MM-DD (§5.1)
	Zoneinfo  string `json:"zoneinfo,omitempty"`  // IANA tz, e.g. "Europe/Paris"
	Locale    string `json:"locale,omitempty"`    // BCP 47, e.g. "en-US"

	UpdatedAt int64 `json:"updated_at,omitempty"` // seconds since Unix epoch
}

// GetIDTokenClaims implements [Claims].
// Any struct embedding IDTokenClaims gets this method for free via promotion.
func (sc *IDTokenClaims) GetIDTokenClaims() *IDTokenClaims { return sc }

// Claims is implemented for free by any struct that embeds [IDTokenClaims].
//
//	type AppClaims struct {
//	    jwt.StandardClaims        // promotes GetIDTokenClaims() - zero boilerplate
//	    RoleList string `json:"roles"`
//	}
type Claims interface {
	GetIDTokenClaims() *IDTokenClaims
}

// Decode parses a compact JWT string (header.payload.signature) into a JWS.
//
// It does not unmarshal the claims payload - call [UnmarshalClaims] after
// [Verifier.VerifyJWT] or [Verifier.Verify] to populate a typed claims struct.
func Decode(tokenStr string) (*JWS, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("%w", ErrMalformedToken)
	}

	var jws JWS
	jws.protected, jws.payload = []byte(parts[0]), []byte(parts[1])

	header, err := base64.RawURLEncoding.DecodeString(string(jws.protected))
	if err != nil {
		return nil, fmt.Errorf("header base64: %w: %w", err, ErrInvalidHeader)
	}
	if err := json.Unmarshal(header, &jws.header); err != nil {
		return nil, fmt.Errorf("header json: %w: %w", err, ErrInvalidHeader)
	}

	jws.signature, err = base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature base64: %w: %w", err, ErrInvalidSignature)
	}

	return &jws, nil
}

// UnmarshalClaims decodes the payload of jws into claims.
//
// Always call [Verifier.VerifyJWT] or [Decode]+[Verifier.Verify] before
// UnmarshalClaims - the signature must be authenticated before trusting the
// payload. Works with any [VerifiableJWS] implementation, not just [*JWS].
func UnmarshalClaims(jws VerifiableJWS, claims Claims) error {
	payload, err := base64.RawURLEncoding.DecodeString(string(jws.GetPayload()))
	if err != nil {
		return fmt.Errorf("invalid claims encoding: %w", err)
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("invalid claims JSON: %w", err)
	}
	return nil
}

// NewJWS creates an unsigned JWS from the provided claims.
//
// The "alg" and "kid" header fields are set automatically by [Signer.SignJWS]
// based on the key type and [jwk.PrivateKey.KID]. Call [Encode] to
// produce the compact JWT string after signing.
func NewJWS(claims Claims) (*JWS, error) {
	var jws JWS

	jws.header.Header = Header{
		// Alg and KID are set by Sign from the key type and jwk.PrivateKey.KID.
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

// Encode produces the compact JWT string (header.payload.signature).
func Encode(jws VerifiableJWS) string {
	protected := jws.GetProtected()
	payload := jws.GetPayload()
	sig := base64.RawURLEncoding.EncodeToString(jws.GetSignature())
	out := make([]byte, 0, len(protected)+1+len(payload)+1+len(sig))
	out = append(out, protected...)
	out = append(out, '.')
	out = append(out, payload...)
	out = append(out, '.')
	out = append(out, sig...)
	return string(out)
}

// signWith is the shared implementation used by [Signer.SignJWS]. It selects
// the algorithm from the key type, validates any
// pre-set alg/kid in the JWS header, then calls [SignableJWS.MarshalHeader]
// and [SignableJWS.SetSignature] so custom JWS types need no crypto knowledge.
//
// pk must have a non-nil Signer. KID is taken from pk.KID - set automatically
// if the header's KID is empty; an error is returned on mismatch.
func signWith(jws SignableJWS, pk *jwk.PrivateKey) error {
	if pk.Signer == nil {
		return fmt.Errorf("signWith: kid %q: %w", pk.KID, ErrNoSigningKey)
	}
	hdr := jws.GetHeader()
	switch {
	case hdr.KID == "":
		hdr.KID = pk.KID
	case hdr.KID != pk.KID:
		return fmt.Errorf("signWith: header kid %q conflicts with key KID %q", hdr.KID, pk.KID)
	}

	switch pub := pk.Signer.Public().(type) {
	case *ecdsa.PublicKey:
		alg, h, err := algForECKey(pub)
		if err != nil {
			return err
		}
		if hdr.Alg != "" && hdr.Alg != alg {
			return fmt.Errorf("signWith: key %s vs header %q: %w", alg, hdr.Alg, ErrAlgConflict)
		}
		hdr.Alg = alg
		protected, err := jws.MarshalHeader(hdr)
		if err != nil {
			return err
		}
		digest, err := digestFor(h, signingInputBytes(protected, jws.GetPayload()))
		if err != nil {
			return err
		}
		// crypto.Signer returns ASN.1 DER for ECDSA; convert to raw r||s for JWS.
		derSig, err := pk.Signer.Sign(rand.Reader, digest, h)
		if err != nil {
			return fmt.Errorf("signWith %s: %w", alg, err)
		}
		sig, err := ecdsaDERToRaw(derSig, pub.Curve)
		if err != nil {
			return err
		}
		jws.SetSignature(sig)
		return nil

	case *rsa.PublicKey:
		if hdr.Alg != "" && hdr.Alg != "RS256" {
			return fmt.Errorf("signWith: RSA vs header %q: %w", hdr.Alg, ErrAlgConflict)
		}
		hdr.Alg = "RS256"
		protected, err := jws.MarshalHeader(hdr)
		if err != nil {
			return err
		}
		digest, err := digestFor(crypto.SHA256, signingInputBytes(protected, jws.GetPayload()))
		if err != nil {
			return err
		}
		// crypto.Signer returns raw PKCS#1 v1.5 bytes for RSA; use directly.
		sig, err := pk.Signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("signWith RS256: %w", err)
		}
		jws.SetSignature(sig)
		return nil

	case ed25519.PublicKey:
		if hdr.Alg != "" && hdr.Alg != "EdDSA" {
			return fmt.Errorf("signWith: EdDSA vs header %q: %w", hdr.Alg, ErrAlgConflict)
		}
		hdr.Alg = "EdDSA"
		protected, err := jws.MarshalHeader(hdr)
		if err != nil {
			return err
		}
		// Ed25519 signs the raw message with no pre-hashing; pass crypto.Hash(0).
		sig, err := pk.Signer.Sign(rand.Reader, signingInputBytes(protected, jws.GetPayload()), crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("signWith EdDSA: %w", err)
		}
		jws.SetSignature(sig)
		return nil

	default:
		return fmt.Errorf(
			"signWith: %T: %w",
			pk.Signer.Public(), ErrUnsupportedKey,
		)
	}
}

// signingInputBytes builds the protected.payload byte slice used as the signing input.
func signingInputBytes(protected, payload []byte) []byte {
	out := make([]byte, 0, len(protected)+1+len(payload))
	out = append(out, protected...)
	out = append(out, '.')
	out = append(out, payload...)
	return out
}

// DefaultGracePeriod is the tolerance applied to exp, iat, and auth_time checks
// when ValidatorCore.GracePeriod is zero.
//
// It should be set to at least 2s in most cases to account for practical edge
// cases of corresponding systems having even a millisecond of clock skew between
// them and the offset of their respective implementations truncating, flooring,
// ceiling, or rounding seconds differently.
//
// For example: If 1.999 is truncated to 1 and 2.001 is ceiled to 3, then there
// is a 2 second difference.
//
// This will very rarely affect calculations on exp (and hopefully a client knows
// better than to ride the very millisecond of expiration), but it can very
// frequently affect calculations on iat and nbf on distributed production
// systems.
var DefaultGracePeriod = 2 * time.Second

// ValidatorCore holds configuration shared by [IDTokenValidator] and [RFCValidator].
// It can also be used directly as a minimal validator.
//
// Exp and Iat are checked by default; set IgnoreExp or IgnoreIat to opt out.
// Iss, Aud, and Azp are allowlists - when non-empty the token's claim value
// must appear in the list and the claim must be present. RequiredAMRs and
// MinAMRCount constrain the amr claim when set.
//
// GracePeriod is applied to exp, iat, and auth_time to tolerate minor clock
// differences between distributed systems. If zero, [DefaultGracePeriod] (5s)
// is used. Set to a negative value to disable skew tolerance entirely.
//
// MaxAge applies to auth_time: when set, authentication must have occurred
// within MaxAge of now.
type ValidatorCore struct {
	GracePeriod  time.Duration // 0 = DefaultGracePeriod (5s); negative = no tolerance
	MaxAge       time.Duration
	IgnoreExp    bool
	IgnoreNBF    bool // rarely appropriate; nbf is a security boundary like exp
	IgnoreIat    bool
	Iss          []string // token's iss must appear in list (if set)
	Aud          []string // token's aud must intersect list (if set)
	Azp          []string // token's azp must appear in list (if set)
	RequiredAMRs []string // all of these must appear in the token's amr list
	MinAMRCount  int      // token's amr must have at least this many values; 0 = no minimum
}

// Validate checks exp, nbf, iat, and any configured value lists (iss, aud, azp, amr).
// It does not check sub, jti, or auth_time - use [IDTokenValidator] or [RFCValidator]
// for those.
//
// Returns nil on success, or an [errors.Join] of all failures. Use [errors.Is]
// to check for specific sentinels (e.g. [ErrTokenExpired], [ErrMissingClaim]).
func (v *ValidatorCore) Validate(claims Claims, now time.Time) error {
	return validateClaims(*claims.GetIDTokenClaims(), *v, claimChecks{
		checkIss: len(v.Iss) > 0,
		checkAud: len(v.Aud) > 0,
		checkExp: !v.IgnoreExp,
		checkNBF: !v.IgnoreNBF,
		checkIat: !v.IgnoreIat,
		checkAMR: len(v.RequiredAMRs) > 0 || v.MinAMRCount > 0,
		checkAzp: len(v.Azp) > 0,
	}, now)
}

// IDTokenValidator checks the OIDC Core §2 unconditionally required claims by default.
// It is the strict counterpart to [RFCValidator].
//
// OIDC unconditionally requires iss, sub, aud, exp, and iat - these are checked
// unless explicitly disabled with Ignore* fields. Exp and Iat are promoted from
// [ValidatorCore]. JTI and AuthTime are opt-in (Expect* fields) because OIDC
// only requires auth_time when max_age was requested. Azp and AMR are driven
// by allowlists in [ValidatorCore] (Azp and RequiredAMRs/MinAMRCount).
//
// Sub is presence-only: it must be non-empty, but its value is not matched -
// per-token/per-user identity checks belong in the application.
//
// Call [IDTokenValidator.Validate] to check the standard fields.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type IDTokenValidator struct {
	ValidatorCore
	IgnoreIss      bool
	IgnoreSub      bool // if false, sub must be present (non-empty)
	IgnoreAud      bool
	ExpectJTI      bool // if true, jti must be present (non-empty)
	ExpectAuthTime bool // if true (or MaxAge > 0), auth_time is validated
}

// Validate checks the OIDC Core §2 ID Token claims.
//
// Returns nil on success, or an [errors.Join] of all failures. Use [errors.Is]
// to check for specific sentinels (e.g. [ErrTokenExpired], [ErrMissingClaim]).
func (v *IDTokenValidator) Validate(claims Claims, now time.Time) error {
	return validateClaims(*claims.GetIDTokenClaims(), v.ValidatorCore, claimChecks{
		checkIss:      !v.IgnoreIss,
		checkSub:      !v.IgnoreSub,
		checkAud:      !v.IgnoreAud,
		checkExp:      !v.IgnoreExp,
		checkNBF:      !v.IgnoreNBF,
		checkIat:      !v.IgnoreIat,
		checkJTI:      v.ExpectJTI,
		checkAuthTime: v.ExpectAuthTime || v.MaxAge > 0,
		checkAMR:      len(v.RequiredAMRs) > 0 || v.MinAMRCount > 0,
		checkAzp:      len(v.Azp) > 0,
	}, now)
}

// RFCValidator checks only the most critical claims by default - exp and iat.
// It is the lax counterpart to [IDTokenValidator], matching RFC 7519 semantics
// where almost all claims are optional.
//
// Exp and Iat are checked by default (IgnoreExp and IgnoreIat from the embedded
// [ValidatorCore] can disable them, but this is rarely appropriate). Iss, Aud,
// and Azp are checked automatically when their value lists are configured.
// Everything else (Sub, JTI, AuthTime, AMR) requires explicit opt-in via
// Expect* fields, expressing that the claim is expected and it is an error if
// it is absent or invalid.
//
// Use RFCValidator when tokens legitimately omit optional claims such as
// amr, jti, or auth_time. Prefer [IDTokenValidator] when you control token
// issuance and want full OIDC compliance enforced.
//
// Call [RFCValidator.Validate] to check claims.
type RFCValidator struct {
	ValidatorCore
	ExpectSub      bool // if true, sub must be present (non-empty)
	ExpectJTI      bool // if true, jti must be present (non-empty)
	ExpectAuthTime bool // if true (or MaxAge > 0), auth_time is validated
	ExpectAMR      bool // if true (or RequiredAMRs/MinAMRCount set), amr is validated
}

// Validate checks claims against RFC 7519 rules.
//
// Returns nil on success, or an [errors.Join] of all failures. Use [errors.Is]
// to check for specific sentinels (e.g. [ErrTokenExpired], [ErrMissingClaim]).
func (v *RFCValidator) Validate(claims Claims, now time.Time) error {
	return validateClaims(*claims.GetIDTokenClaims(), v.ValidatorCore, claimChecks{
		checkIss:      len(v.Iss) > 0,
		checkSub:      v.ExpectSub,
		checkAud:      len(v.Aud) > 0,
		checkExp:      !v.IgnoreExp,
		checkNBF:      !v.IgnoreNBF,
		checkIat:      !v.IgnoreIat,
		checkJTI:      v.ExpectJTI,
		checkAuthTime: v.ExpectAuthTime || v.MaxAge > 0,
		checkAMR:      v.ExpectAMR || len(v.RequiredAMRs) > 0 || v.MinAMRCount > 0,
		checkAzp:      len(v.Azp) > 0,
	}, now)
}

// claimChecks holds the resolved per-check flags computed from a validator
// before passing to [validateClaims].
type claimChecks struct {
	checkIss      bool
	checkSub      bool
	checkAud      bool
	checkExp      bool
	checkNBF      bool
	checkIat      bool
	checkJTI      bool
	checkAuthTime bool
	checkAMR      bool
	checkAzp      bool
}

func validateClaims(claims IDTokenClaims, core ValidatorCore, checks claimChecks, now time.Time) error {
	var errs []error

	skew := core.GracePeriod
	if skew == 0 {
		skew = DefaultGracePeriod
	} else if skew < 0 {
		skew = 0
	}

	if checks.checkIss {
		if claims.Iss == "" {
			errs = append(errs, fmt.Errorf("iss: %w", ErrMissingClaim))
		} else if len(core.Iss) > 0 && !slices.Contains(core.Iss, claims.Iss) {
			errs = append(errs, fmt.Errorf("iss %q not in allowed list: %w", claims.Iss, ErrInvalidClaim))
		}
	}

	if checks.checkSub && claims.Sub == "" {
		errs = append(errs, fmt.Errorf("sub: %w", ErrMissingClaim))
	}

	if checks.checkAud {
		if len(claims.Aud) == 0 {
			errs = append(errs, fmt.Errorf("aud: %w", ErrMissingClaim))
		} else if len(core.Aud) > 0 && !slices.ContainsFunc([]string(claims.Aud), func(a string) bool {
			return slices.Contains(core.Aud, a)
		}) {
			errs = append(errs, fmt.Errorf("aud %v not in allowed list: %w", claims.Aud, ErrInvalidClaim))
		}
	}

	if checks.checkExp {
		if claims.Exp <= 0 {
			errs = append(errs, fmt.Errorf("exp: %w", ErrMissingClaim))
		} else if now.After(time.Unix(claims.Exp, 0).Add(skew)) {
			duration := now.Sub(time.Unix(claims.Exp, 0))
			expTime := time.Unix(claims.Exp, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Errorf("expired %s ago (%s): %w", formatDuration(duration), expTime, ErrTokenExpired))
		}
	}

	// nbf is only validated when present (non-zero); absence is never an error.
	if checks.checkNBF && claims.NBF > 0 {
		nbfTime := time.Unix(claims.NBF, 0)
		if nbfTime.After(now.Add(skew)) {
			fromNow := nbfTime.Sub(now)
			nbfStr := nbfTime.Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Errorf("nbf is %s in the future (%s): %w", formatDuration(fromNow), nbfStr, ErrTokenNotYetValid))
		}
	}

	if checks.checkIat {
		if claims.Iat <= 0 {
			errs = append(errs, fmt.Errorf("iat: %w", ErrMissingClaim))
		} else if time.Unix(claims.Iat, 0).After(now.Add(skew)) {
			duration := time.Unix(claims.Iat, 0).Sub(now)
			iatTime := time.Unix(claims.Iat, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Errorf("iat is %s in the future (%s): %w", formatDuration(duration), iatTime, ErrTokenFromFuture))
		}
	}

	if checks.checkJTI && claims.JTI == "" {
		errs = append(errs, fmt.Errorf("jti: %w", ErrMissingClaim))
	}

	if checks.checkAuthTime {
		if claims.AuthTime == 0 {
			errs = append(errs, fmt.Errorf("auth_time: %w", ErrMissingClaim))
		} else {
			authTime := time.Unix(claims.AuthTime, 0)
			authTimeStr := authTime.Format("2006-01-02 15:04:05 MST")
			age := now.Sub(authTime)
			if authTime.After(now.Add(skew)) {
				fromNow := authTime.Sub(now)
				errs = append(errs, fmt.Errorf(
					"auth_time %s is %s in the future: %w",
					authTimeStr, formatDuration(fromNow), ErrTokenFromFuture),
				)
			} else if core.MaxAge > 0 && age > core.MaxAge {
				diff := age - core.MaxAge
				errs = append(errs, fmt.Errorf(
					"auth_time %s is %s old, exceeding max age %s by %s: %w",
					authTimeStr, formatDuration(age), formatDuration(core.MaxAge), formatDuration(diff), ErrAuthTooOld),
				)
			}
		}
	}

	if checks.checkAMR {
		if len(claims.AMR) == 0 {
			errs = append(errs, fmt.Errorf("amr: %w", ErrMissingClaim))
		} else {
			for _, required := range core.RequiredAMRs {
				if !slices.Contains(claims.AMR, required) {
					errs = append(errs, fmt.Errorf("amr missing %q: %w", required, ErrInvalidClaim))
				}
			}
			if core.MinAMRCount > 0 && len(claims.AMR) < core.MinAMRCount {
				errs = append(errs, fmt.Errorf("amr has %d factor(s), need at least %d: %w", len(claims.AMR), core.MinAMRCount, ErrInvalidClaim))
			}
		}
	}

	if checks.checkAzp && len(core.Azp) > 0 && !slices.Contains(core.Azp, claims.Azp) {
		errs = append(errs, fmt.Errorf("azp %q not in allowed list: %w", claims.Azp, ErrInvalidClaim))
	}

	if len(errs) > 0 {
		// time.Local is loaded once at process start - no LoadLocation syscall needed.
		serverTime := fmt.Sprintf("server time %s (%s)", now.Format("2006-01-02 15:04:05 MST"), time.Local)
		errs = append(errs, fmt.Errorf("%s: %w", serverTime, ErrValidation))
		return errors.Join(errs...)
	}
	return nil
}

// Verifier holds the public keys of a JWT issuer and verifies token signatures.
//
// In OIDC terminology, the "issuer" is the identity provider that both signs
// tokens and publishes its public keys. Verifier represents that issuer from
// the relying party's perspective - you hold its public keys and use them to
// verify that tokens were legitimately signed by it.
//
// Verifier is immutable after construction - safe for concurrent use with no locking.
// Use [New] to construct with a fixed key set, or use [Signer.Verifier] or
// [KeyFetcher.Verifier] to obtain one from a signer or remote JWKS endpoint.
type Verifier struct {
	pubKeys []jwk.PublicKey
	keys    map[string]jwk.CryptoPublicKey // kid => key
}

// New creates a Verifier with an explicit set of public keys.
//
// The returned Verifier is immutable - keys cannot be added or removed after
// construction. For dynamic key rotation, see [KeyFetcher].
func New(keys []jwk.PublicKey) *Verifier {
	m := make(map[string]jwk.CryptoPublicKey, len(keys))
	for _, k := range keys {
		m[k.KID] = k.CryptoPublicKey
	}
	return &Verifier{
		pubKeys: keys,
		keys:    m,
	}
}

// PublicKeys returns the public keys held by this Verifier.
//
// To serialize as a JWKS JSON document:
//
//	json.Marshal(jwk.JWKs{Keys: verifier.PublicKeys()})
func (iss *Verifier) PublicKeys() []jwk.PublicKey {
	return iss.pubKeys
}

// Verify checks the signature of an already-decoded [VerifiableJWS].
//
// Returns nil on success, a descriptive error on failure. Claim values
// (iss, aud, exp, etc.) are NOT checked - call [Validator.Validate] on the
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
func (iss *Verifier) Verify(jws VerifiableJWS) error {
	h := jws.GetHeader()
	if h.KID == "" {
		return fmt.Errorf("%w", ErrMissingKID)
	}
	key, ok := iss.keys[h.KID]
	if !ok {
		return fmt.Errorf("kid %q: %w", h.KID, ErrUnknownKID)
	}

	protected, payload := jws.GetProtected(), jws.GetPayload()
	signingInput := make([]byte, 0, len(protected)+1+len(payload))
	signingInput = append(signingInput, protected...)
	signingInput = append(signingInput, '.')
	signingInput = append(signingInput, payload...)
	if err := verifyWith(signingInput, jws.GetSignature(), h.Alg, key); err != nil {
		return fmt.Errorf("kid %q alg %q: %w", h.KID, h.Alg, err)
	}
	return nil
}

// VerifyJWT decodes tokenStr and verifies its signature, returning the parsed
// [*JWS] on success.
//
// Returns (nil, err) on any failure - the caller never receives an
// unauthenticated JWS. Claim values (iss, aud, exp, etc.) are NOT checked;
// call [IDTokenValidator.Validate] or [RFCValidator.Validate] on the unmarshalled claims after VerifyJWT:
//
//	jws, err := iss.VerifyJWT(tokenStr)
//	if err != nil { /* bad sig, malformed token, unknown kid */ }
//	var claims AppClaims
//	if err := jwt.UnmarshalClaims(jws, &claims); err != nil { /* ... */ }
//	if err := v.Validate(&claims, time.Now()); err != nil { /* ... */ }
//
// For routing by kid/iss before verifying, use [Decode] then [Verifier.Verify].
func (iss *Verifier) VerifyJWT(tokenStr string) (*JWS, error) {
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
func verifyWith(signingInput []byte, sig []byte, alg string, key jwk.CryptoPublicKey) error {
	switch alg {
	case "ES256", "ES384", "ES512":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg %s requires *ecdsa.PublicKey, got %T: %w", alg, key, ErrKeyTypeMismatch)
		}
		expectedAlg, h, err := algForECKey(k)
		if err != nil {
			return err
		}
		if expectedAlg != alg {
			return fmt.Errorf("key is %s, token alg is %s: %w", expectedAlg, alg, ErrCurveMismatch)
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		if len(sig) != 2*byteLen {
			return fmt.Errorf("%s sig len %d, want %d: %w", alg, len(sig), 2*byteLen, ErrSignatureInvalid)
		}
		digest, err := digestFor(h, signingInput)
		if err != nil {
			return err
		}
		r := new(big.Int).SetBytes(sig[:byteLen])
		s := new(big.Int).SetBytes(sig[byteLen:])
		if !ecdsa.Verify(k, digest, r, s) {
			return fmt.Errorf("%s: %w", alg, ErrSignatureInvalid)
		}
		return nil

	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("alg RS256 requires *rsa.PublicKey, got %T: %w", key, ErrKeyTypeMismatch)
		}
		digest, err := digestFor(crypto.SHA256, signingInput)
		if err != nil {
			return err
		}
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig); err != nil {
			return fmt.Errorf("RS256: %w: %w", err, ErrSignatureInvalid)
		}
		return nil

	case "EdDSA":
		k, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("alg EdDSA requires ed25519.PublicKey, got %T: %w", key, ErrKeyTypeMismatch)
		}
		if !ed25519.Verify(k, signingInput, sig) {
			return fmt.Errorf("EdDSA: %w", ErrSignatureInvalid)
		}
		return nil

	default:
		return fmt.Errorf("alg %q: %w", alg, ErrUnsupportedAlg)
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
		return "", 0, fmt.Errorf("EC curve %s: %w", pub.Curve.Params().Name, ErrUnsupportedKey)
	}
}

func digestFor(h crypto.Hash, data []byte) ([]byte, error) {
	if !h.Available() {
		return nil, fmt.Errorf("jwt: unsupported hash %v", h)
	}
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil), nil
}

func ecdsaDERToRaw(der []byte, curve elliptic.Curve) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, fmt.Errorf("ecdsaDERToRaw: %w", err)
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("ecdsaDERToRaw: %d unexpected trailing bytes after signature", len(rest))
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
	if seconds > 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	if len(parts) == 0 {
		// Sub-second duration: fall back to milliseconds.
		d -= time.Duration(seconds) * time.Second
		millis := int(d / time.Millisecond)
		parts = append(parts, fmt.Sprintf("%dms", millis))
	}

	return strings.Join(parts, " ")
}
