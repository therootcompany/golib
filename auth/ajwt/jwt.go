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
//   - [ValidateParams] is a stable config object; time is passed at the call
//     site so the same params can be reused across requests.
//   - [JWS.UnmarshalClaims] accepts any type — no interface to implement.
//   - [JWS.Sign] uses [crypto.Signer] for ES256 (P-256), ES384 (P-384),
//     ES512 (P-521), RS256 (RSA PKCS#1 v1.5), and EdDSA (Ed25519/RFC 8037).
//
// Typical usage:
//
//	// At startup:
//	iss := ajwt.NewIssuer("https://accounts.example.com")
//	iss.Params = ajwt.ValidateParams{Aud: "my-app", IgnoreIss: true}
//	if err := iss.FetchKeys(ctx); err != nil { ... }
//
//	// Per request:
//	jws, err := ajwt.Decode(tokenStr)
//	if err := iss.Verify(jws); err != nil { ... }   // sig + iss check
//	var claims AppClaims
//	if err := jws.UnmarshalClaims(&claims); err != nil { ... }
//	if errs, err := iss.Params.Validate(claims.StandardClaims, time.Now()); err != nil { ... }
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
	"net/http"
	"slices"
	"strings"
	"time"
)

// JWS is a decoded JSON Web Signature / JWT.
//
// It holds only the parsed structure — header, raw base64url fields, and
// decoded signature bytes. It carries no Claims interface and no Verified flag;
// use [Issuer.Verify] to authenticate the token and [JWS.UnmarshalClaims] to
// decode the payload into a typed struct.
type JWS struct {
	Protected string        // base64url-encoded header
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
// Embed StandardClaims in your own claims struct:
//
//	type AppClaims struct {
//	    ajwt.StandardClaims
//	    Email string `json:"email"`
//	}
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

// Decode parses a compact JWT string (header.payload.signature) into a JWS.
//
// It does not unmarshal the claims payload — call [JWS.UnmarshalClaims] after
// [Issuer.Verify] to populate a typed claims struct.
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
// [Issuer.Verify] before UnmarshalClaims to ensure the signature is
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

// ValidateParams holds claim validation configuration.
//
// Configure once at startup; call [ValidateParams.Validate] per request,
// passing the current time. This keeps the config stable and makes the
// time dependency explicit at the call site.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type ValidateParams struct {
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

// Validate checks the standard JWT/OIDC claim fields against this config.
//
// now is typically time.Now() — passing it explicitly keeps the config stable
// across requests and avoids hidden time dependencies in the params struct.
func (p ValidateParams) Validate(claims StandardClaims, now time.Time) ([]string, error) {
	return ValidateStandardClaims(claims, p, now)
}

// ValidateStandardClaims checks the registered JWT/OIDC claim fields against params.
//
// Exported so callers can use it directly without a [ValidateParams] receiver:
//
//	errs, err := ajwt.ValidateStandardClaims(claims.StandardClaims, params, time.Now())
func ValidateStandardClaims(claims StandardClaims, params ValidateParams, now time.Time) ([]string, error) {
	var errs []string

	// Required to exist and match
	if len(params.Iss) > 0 || !params.IgnoreIss {
		if len(claims.Iss) == 0 {
			errs = append(errs, "missing or malformed 'iss' (token issuer, identifier for public key)")
		} else if claims.Iss != params.Iss {
			errs = append(errs, fmt.Sprintf("'iss' (token issuer) mismatch: got %s, expected %s", claims.Iss, params.Iss))
		}
	}

	// Required to exist, optional match
	if len(claims.Sub) == 0 {
		if !params.IgnoreSub {
			errs = append(errs, "missing or malformed 'sub' (subject, typically pairwise user id)")
		}
	} else if len(params.Sub) > 0 {
		if params.Sub != claims.Sub {
			errs = append(errs, fmt.Sprintf("'sub' (subject) mismatch: got %s, expected %s", claims.Sub, params.Sub))
		}
	}

	// Required to exist and match
	if len(params.Aud) > 0 || !params.IgnoreAud {
		if len(claims.Aud) == 0 {
			errs = append(errs, "missing or malformed 'aud' (audience receiving token)")
		} else if claims.Aud != params.Aud {
			errs = append(errs, fmt.Sprintf("'aud' (audience) mismatch: got %s, expected %s", claims.Aud, params.Aud))
		}
	}

	// Required to exist and not be in the past
	if !params.IgnoreExp {
		if claims.Exp <= 0 {
			errs = append(errs, "missing or malformed 'exp' (expiration date in seconds)")
		} else if claims.Exp < now.Unix() {
			duration := now.Sub(time.Unix(claims.Exp, 0))
			expTime := time.Unix(claims.Exp, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("token expired %s ago (%s)", formatDuration(duration), expTime))
		}
	}

	// Required to exist and not be in the future
	if !params.IgnoreIat {
		if claims.Iat <= 0 {
			errs = append(errs, "missing or malformed 'iat' (issued at, when token was signed)")
		} else if claims.Iat > now.Unix() {
			duration := time.Unix(claims.Iat, 0).Sub(now)
			iatTime := time.Unix(claims.Iat, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("'iat' (issued at) is %s in the future (%s)", formatDuration(duration), iatTime))
		}
	}

	// Should exist, in the past, with optional max age
	if params.MaxAge > 0 || !params.IgnoreAuthTime {
		if claims.AuthTime == 0 {
			errs = append(errs, "missing or malformed 'auth_time' (time of real-world user authentication, in seconds)")
		} else {
			authTime := time.Unix(claims.AuthTime, 0)
			authTimeStr := authTime.Format("2006-01-02 15:04:05 MST")
			age := now.Sub(authTime)
			diff := age - params.MaxAge
			if claims.AuthTime > now.Unix() {
				fromNow := time.Unix(claims.AuthTime, 0).Sub(now)
				errs = append(errs, fmt.Sprintf(
					"'auth_time' of %s is %s in the future (server time %s)",
					authTimeStr, formatDuration(fromNow), now.Format("2006-01-02 15:04:05 MST")),
				)
			} else if params.MaxAge > 0 && age > params.MaxAge {
				errs = append(errs, fmt.Sprintf(
					"'auth_time' of %s is %s old, exceeding max age %s by %s",
					authTimeStr, formatDuration(age), formatDuration(params.MaxAge), formatDuration(diff)),
				)
			}
		}
	}

	// Optional exact match
	if params.Jti != claims.Jti {
		if len(params.Jti) > 0 {
			errs = append(errs, fmt.Sprintf("'jti' (jwt id) mismatch: got %s, expected %s", claims.Jti, params.Jti))
		} else if !params.IgnoreJti {
			errs = append(errs, fmt.Sprintf("unchecked 'jti' (jwt id): %s", claims.Jti))
		}
	}

	// Optional exact match
	if params.Nonce != claims.Nonce {
		if len(params.Nonce) > 0 {
			errs = append(errs, fmt.Sprintf("'nonce' mismatch: got %s, expected %s", claims.Nonce, params.Nonce))
		} else if !params.IgnoreNonce {
			errs = append(errs, fmt.Sprintf("unchecked 'nonce': %s", claims.Nonce))
		}
	}

	// Should exist, optional required-set check
	if !params.IgnoreAmr {
		if len(claims.Amr) == 0 {
			errs = append(errs, "missing or malformed 'amr' (authorization methods, as json list)")
		} else if len(params.RequiredAmrs) > 0 {
			for _, required := range params.RequiredAmrs {
				if !slices.Contains(claims.Amr, required) {
					errs = append(errs, fmt.Sprintf("missing required '%s' from 'amr'", required))
				}
			}
		}
	}

	// Optional, match if present
	if params.Azp != claims.Azp {
		if len(params.Azp) > 0 {
			errs = append(errs, fmt.Sprintf("'azp' (authorized party) mismatch: got %s, expected %s", claims.Azp, params.Azp))
		} else if !params.IgnoreAzp {
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

// Issuer holds public keys and validation config for a trusted token issuer.
//
// [Issuer.FetchKeys] loads keys from the issuer's JWKS endpoint.
// [Issuer.SetKeys] injects keys directly (useful in tests).
// [Issuer.Verify] authenticates the token: key lookup → sig verify → iss check.
//
// Typical setup:
//
//	iss := ajwt.NewIssuer("https://accounts.example.com")
//	iss.Params = ajwt.ValidateParams{Aud: "my-app", IgnoreIss: true}
//	if err := iss.FetchKeys(ctx); err != nil { ... }
type Issuer struct {
	URL     string
	JWKsURL string // optional; defaults to URL + "/.well-known/jwks.json"
	Params  ValidateParams
	keys    map[string]crypto.PublicKey // kid → key
}

// NewIssuer creates an Issuer for the given base URL.
func NewIssuer(url string) *Issuer {
	return &Issuer{
		URL:  url,
		keys: make(map[string]crypto.PublicKey),
	}
}

// SetKeys stores public keys by their KID, replacing any previously stored keys.
// Useful for injecting keys in tests without an HTTP round-trip.
func (iss *Issuer) SetKeys(keys []PublicJWK) {
	m := make(map[string]crypto.PublicKey, len(keys))
	for _, k := range keys {
		m[k.KID] = k.Key
	}
	iss.keys = m
}

// FetchKeys retrieves and stores the JWKS from the issuer's endpoint.
// If JWKsURL is empty, it defaults to URL + "/.well-known/jwks.json".
func (iss *Issuer) FetchKeys(ctx context.Context) error {
	url := iss.JWKsURL
	if url == "" {
		url = strings.TrimRight(iss.URL, "/") + "/.well-known/jwks.json"
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("fetch JWKS: unexpected status %d", resp.StatusCode)
	}

	keys, err := DecodePublicJWKs(resp.Body)
	if err != nil {
		return fmt.Errorf("parse JWKS: %w", err)
	}

	iss.SetKeys(keys)
	return nil
}

// Verify authenticates jws against this issuer:
//  1. Looks up the signing key by jws.Header.Kid.
//  2. Verifies the signature before trusting any payload data.
//  3. Checks that the token's "iss" claim matches iss.URL.
//
// Call [JWS.UnmarshalClaims] after Verify to safely decode the payload into a
// typed struct, then [ValidateParams.Validate] to check claim values.
func (iss *Issuer) Verify(jws *JWS) error {
	if jws.Header.Kid == "" {
		return fmt.Errorf("missing 'kid' header")
	}
	key, ok := iss.keys[jws.Header.Kid]
	if !ok {
		return fmt.Errorf("unknown kid: %q", jws.Header.Kid)
	}

	signingInput := jws.Protected + "." + jws.Payload
	if err := verifyWith(signingInput, jws.Signature, jws.Header.Alg, key); err != nil {
		return fmt.Errorf("signature verification failed: %w", err)
	}

	// Signature verified — now safe to inspect the payload.
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return fmt.Errorf("invalid claims encoding: %w", err)
	}
	var partial struct {
		Iss string `json:"iss"`
	}
	if err := json.Unmarshal(payload, &partial); err != nil {
		return fmt.Errorf("invalid claims JSON: %w", err)
	}
	if partial.Iss != iss.URL {
		return fmt.Errorf("iss mismatch: got %q, want %q", partial.Iss, iss.URL)
	}

	return nil
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
