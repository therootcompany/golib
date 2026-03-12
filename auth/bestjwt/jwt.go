// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Package bestjwt is a lightweight JWT/JWS/JWK library that combines the
// best ergonomics from the genericjwt and embeddedjwt packages:
//
//   - Claims via embedded structs: Decode(token, &myClaims) — no generics at
//     call sites, no type assertions to access custom fields.
//   - crypto.Signer for all signing: works with in-process keys AND
//     hardware-backed keys (HSM, cloud KMS, PKCS#11) without modification.
//   - Full ECDSA curve support: ES256 (P-256), ES384 (P-384), ES512 (P-521).
//     The algorithm is inferred from the key's curve, not hardcoded.
//   - Curve/algorithm consistency enforcement: UnsafeVerify rejects a P-256
//     key presented for an ES384 token and vice versa.
//   - Generic PublicJWK[K Key]: type-safe JWKS key management with TypedKeys
//     to filter a mixed []PublicJWK[Key] to a concrete key type.
package bestjwt

import (
	"crypto"
	"crypto/ecdsa"
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

// Claims is the interface that custom claims types must satisfy.
//
// Because [StandardClaims] implements Claims with a value receiver, any struct
// that embeds StandardClaims satisfies Claims automatically via method
// promotion — no boilerplate required:
//
//	type AppClaims struct {
//	    bestjwt.StandardClaims
//	    Email string `json:"email"`
//	}
//	// AppClaims now satisfies Claims for free.
//
// Override Validate on the outer struct to add application-specific checks.
// Call [ValidateStandardClaims] inside your override to preserve all standard
// OIDC/JWT validation.
type Claims interface {
	Validate(params ValidateParams) ([]string, error)
}

// JWS is a decoded JSON Web Signature / JWT.
//
// Claims is stored as the [Claims] interface so that any embedded-struct type
// can be used without generics. The most ergonomic access pattern is via the
// pointer you passed to [Decode]:
//
//	var claims AppClaims
//	jws, err := bestjwt.Decode(tokenString, &claims)
//	jws.UnsafeVerify(pubKey)
//	errs, err := jws.Validate(params)
//	// Access claims.Email, claims.Roles, etc. directly — no type assertion.
type JWS struct {
	Protected string         `json:"-"`      // base64url-encoded header
	Header    StandardHeader `json:"header"`
	Payload   string         `json:"-"`      // base64url-encoded claims
	Claims    Claims         `json:"claims"`
	Signature URLBase64      `json:"signature"`
	Verified  bool           `json:"-"`
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
// Embed StandardClaims in your own struct to satisfy [Claims] automatically:
//
//	type AppClaims struct {
//	    bestjwt.StandardClaims
//	    Email string `json:"email"`
//	}
//	// AppClaims now satisfies Claims via promoted Validate.
//	// Override Validate on AppClaims to add custom checks.
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

// Validate implements [Claims] by checking all standard OIDC/JWT claim fields.
//
// This method is promoted to any struct that embeds [StandardClaims], so
// embedding structs satisfy Claims without writing any additional code.
// params.Now must be non-zero; [JWS.Validate] ensures this before delegating.
func (c StandardClaims) Validate(params ValidateParams) ([]string, error) {
	return ValidateStandardClaims(c, params)
}

// Decode parses a compact JWT string (header.payload.signature) into a JWS.
//
// claims must be a pointer to the caller's pre-allocated claims struct
// (e.g. &AppClaims{}). The JSON payload is unmarshaled directly into it,
// and the same pointer is stored in jws.Claims. Callers can access custom
// fields through their own variable without a type assertion:
//
//	var claims AppClaims
//	jws, err := bestjwt.Decode(token, &claims)
//	// claims.Email is already set; no type assertion needed.
//
// The signature is not verified by Decode. Call [JWS.UnsafeVerify] first,
// then [JWS.Validate].
func Decode(tokenStr string, claims Claims) (*JWS, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		return nil, fmt.Errorf("invalid JWT format")
	}

	var jws JWS
	var sigEnc string
	jws.Protected, jws.Payload, sigEnc = parts[0], parts[1], parts[2]

	header, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return nil, fmt.Errorf("invalid header encoding: %v", err)
	}
	if err := json.Unmarshal(header, &jws.Header); err != nil {
		return nil, fmt.Errorf("invalid header JSON: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return nil, fmt.Errorf("invalid claims encoding: %v", err)
	}
	// Unmarshal into the concrete type behind the Claims interface.
	// json.Unmarshal reaches the concrete pointer via reflection.
	if err := json.Unmarshal(payload, claims); err != nil {
		return nil, fmt.Errorf("invalid claims JSON: %v", err)
	}

	if err := jws.Signature.UnmarshalJSON([]byte(sigEnc)); err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %v", err)
	}

	jws.Claims = claims
	return &jws, nil
}

// NewJWSFromClaims creates an unsigned JWS from the provided claims.
//
// kid identifies the signing key. The "alg" header field is set automatically
// when [JWS.Sign] is called, since only the key type determines the algorithm.
// Call [JWS.Encode] to produce a compact JWT string after signing.
func NewJWSFromClaims(claims Claims, kid string) (*JWS, error) {
	var jws JWS

	jws.Header = StandardHeader{
		// Alg is intentionally omitted here; Sign sets it from the key type.
		Kid: kid,
		Typ: "JWT",
	}
	headerJSON, _ := json.Marshal(jws.Header)
	jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

	claimsJSON, _ := json.Marshal(claims)
	jws.Payload = base64.RawURLEncoding.EncodeToString(claimsJSON)
	jws.Claims = claims

	return &jws, nil
}

// Sign signs the JWS in-place using the provided [crypto.Signer].
//
// The algorithm is determined from the signer's public key type and, for EC
// keys, from the curve. The "alg" header field is set and the protected header
// is re-encoded before computing the signing input, so the signed bytes are
// always consistent with the token header.
//
// Supported algorithms (inferred automatically):
//   - *ecdsa.PublicKey P-256 → ES256 (ECDSA + SHA-256, raw r||s)
//   - *ecdsa.PublicKey P-384 → ES384 (ECDSA + SHA-384, raw r||s)
//   - *ecdsa.PublicKey P-521 → ES512 (ECDSA + SHA-512, raw r||s)
//   - *rsa.PublicKey          → RS256 (PKCS#1 v1.5 + SHA-256)
//
// Because the parameter is [crypto.Signer] rather than a concrete key type,
// hardware-backed signers (HSM, OS keychain, cloud KMS) work transparently.
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

	default:
		return nil, fmt.Errorf(
			"Sign: unsupported public key type %T (supported: *ecdsa.PublicKey, *rsa.PublicKey)",
			key.Public(),
		)
	}
}

// Encode produces the compact JWT string (header.payload.signature).
func (jws JWS) Encode() string {
	sigEnc := base64.RawURLEncoding.EncodeToString(jws.Signature)
	return jws.Protected + "." + jws.Payload + "." + sigEnc
}

// UnsafeVerify checks the signature using the algorithm in the JWT header and
// sets jws.Verified on success. It only checks the signature — use
// [JWS.Validate] to check claim values (expiry, issuer, audience, etc.).
//
// pub must be of the concrete type matching the header alg (e.g.
// *ecdsa.PublicKey for ES256/ES384/ES512). Callers can pass PublicJWK.Key
// directly without a type assertion.
//
// For ECDSA tokens, the key's curve is checked against the claimed algorithm
// (e.g. P-384 key is rejected for an ES256 token) to prevent cross-algorithm
// downgrade attacks.
//
// Currently supported: ES256, ES384, ES512, RS256.
func (jws *JWS) UnsafeVerify(pub Key) bool {
	signingInput := jws.Protected + "." + jws.Payload

	switch jws.Header.Alg {
	case "ES256", "ES384", "ES512":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || k == nil {
			jws.Verified = false
			return false
		}
		// Require the key's curve to match the token's claimed algorithm.
		// A P-256 key must not verify an ES384 token and vice versa.
		expectedAlg, h, err := algForECKey(k)
		if err != nil || expectedAlg != jws.Header.Alg {
			jws.Verified = false
			return false
		}
		byteLen := (k.Curve.Params().BitSize + 7) / 8
		if len(jws.Signature) != 2*byteLen {
			jws.Verified = false
			return false
		}
		digest := digestFor(h, signingInput)
		r := new(big.Int).SetBytes(jws.Signature[:byteLen])
		s := new(big.Int).SetBytes(jws.Signature[byteLen:])
		jws.Verified = ecdsa.Verify(k, digest, r, s)

	case "RS256":
		k, ok := pub.(*rsa.PublicKey)
		if !ok || k == nil {
			jws.Verified = false
			return false
		}
		digest := digestFor(crypto.SHA256, signingInput)
		jws.Verified = rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, jws.Signature) == nil

	default:
		jws.Verified = false
	}
	return jws.Verified
}

// Validate sets params.Now if zero, then delegates to jws.Claims.Validate and
// additionally enforces that the signature was verified (unless params.IgnoreSig).
//
// Returns a list of human-readable errors and a non-nil sentinel if any exist.
func (jws *JWS) Validate(params ValidateParams) ([]string, error) {
	if params.Now.IsZero() {
		params.Now = time.Now()
	}

	errs, _ := jws.Claims.Validate(params)

	if !params.IgnoreSig && !jws.Verified {
		errs = append(errs, "signature was not checked")
	}

	if len(errs) > 0 {
		timeInfo := fmt.Sprintf("info: server time is %s", params.Now.Format("2006-01-02 15:04:05 MST"))
		if loc, err := time.LoadLocation("Local"); err == nil {
			timeInfo += fmt.Sprintf(" %s", loc)
		}
		errs = append(errs, timeInfo)
		return errs, fmt.Errorf("has errors")
	}
	return nil, nil
}

// ValidateParams holds validation configuration.
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
type ValidateParams struct {
	Now            time.Time
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
	IgnoreSig      bool
}

// ValidateStandardClaims checks the registered JWT/OIDC claim fields.
//
// Called by [StandardClaims.Validate] and exported so that custom claims types
// can call it from an overriding Validate method:
//
//	func (c AppClaims) Validate(params bestjwt.ValidateParams) ([]string, error) {
//	    errs, _ := bestjwt.ValidateStandardClaims(c.StandardClaims, params)
//	    if c.Email == "" {
//	        errs = append(errs, "missing email claim")
//	    }
//	    if len(errs) > 0 {
//	        return errs, fmt.Errorf("has errors")
//	    }
//	    return nil, nil
//	}
//
// params.Now must be non-zero; [JWS.Validate] ensures this before delegating.
func ValidateStandardClaims(claims StandardClaims, params ValidateParams) ([]string, error) {
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
		} else if claims.Exp < params.Now.Unix() {
			duration := time.Since(time.Unix(claims.Exp, 0))
			expTime := time.Unix(claims.Exp, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("token expired %s ago (%s)", formatDuration(duration), expTime))
		}
	}

	// Required to exist and not be in the future
	if !params.IgnoreIat {
		if claims.Iat <= 0 {
			errs = append(errs, "missing or malformed 'iat' (issued at, when token was signed)")
		} else if claims.Iat > params.Now.Unix() {
			duration := time.Unix(claims.Iat, 0).Sub(params.Now)
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
			age := params.Now.Sub(authTime)
			diff := age - params.MaxAge
			if claims.AuthTime > params.Now.Unix() {
				fromNow := time.Unix(claims.AuthTime, 0).Sub(params.Now)
				errs = append(errs, fmt.Sprintf(
					"'auth_time' of %s is %s in the future (server time %s)",
					authTimeStr, formatDuration(fromNow), params.Now.Format("2006-01-02 15:04:05 MST")),
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
		return errs, fmt.Errorf("has errors")
	}
	return nil, nil
}

// --- Signing helpers ---

// SignES256 computes an ES256 signature over header.payload using a P-256 key.
// The signature is a fixed-width 64-byte raw r||s value (not ASN.1 DER).
// Each component is zero-padded to 32 bytes via [big.Int.FillBytes].
func SignES256(header, payload string, key *ecdsa.PrivateKey) ([]byte, error) {
	return signEC(header, payload, key, crypto.SHA256)
}

// SignES384 computes an ES384 signature over header.payload using a P-384 key.
// The signature is a fixed-width 96-byte raw r||s value.
func SignES384(header, payload string, key *ecdsa.PrivateKey) ([]byte, error) {
	return signEC(header, payload, key, crypto.SHA384)
}

// SignES512 computes an ES512 signature over header.payload using a P-521 key.
// The signature is a fixed-width 132-byte raw r||s value.
func SignES512(header, payload string, key *ecdsa.PrivateKey) ([]byte, error) {
	return signEC(header, payload, key, crypto.SHA512)
}

// SignRS256 computes an RS256 (PKCS#1 v1.5 + SHA-256) signature over header.payload.
func SignRS256(header, payload string, key *rsa.PrivateKey) ([]byte, error) {
	digest := digestFor(crypto.SHA256, header+"."+payload)
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest)
	if err != nil {
		return nil, fmt.Errorf("SignRS256: %w", err)
	}
	return sig, nil
}

// EncodeToJWT appends a base64url-encoded signature to a signing input string.
func EncodeToJWT(signingInput string, signature []byte) string {
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

// --- EC private key JWK utilities ---

// JWK represents a private key in JSON Web Key format (EC only).
type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	D   string `json:"d"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

// UnmarshalJWK parses an EC private key from a JWK struct.
func UnmarshalJWK(jwk JWK) (*ecdsa.PrivateKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK X: %v", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK Y: %v", err)
	}
	d, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, fmt.Errorf("invalid JWK D: %v", err)
	}

	return &ecdsa.PrivateKey{
		PublicKey: ecdsa.PublicKey{
			Curve: elliptic.P256(),
			X:     new(big.Int).SetBytes(x),
			Y:     new(big.Int).SetBytes(y),
		},
		D: new(big.Int).SetBytes(d),
	}, nil
}

// Thumbprint computes the RFC 7638 JWK Thumbprint for an EC public key.
func (jwk JWK) Thumbprint() (string, error) {
	data := map[string]string{
		"crv": jwk.Crv,
		"kty": jwk.Kty,
		"x":   jwk.X,
		"y":   jwk.Y,
	}
	jsonData, err := json.Marshal(data)
	if err != nil {
		return "", err
	}
	hash := sha256.Sum256(jsonData)
	return base64.RawURLEncoding.EncodeToString(hash[:]), nil
}

// --- Internal helpers ---

// algForECKey returns the JWA algorithm name and hash function for an EC public
// key, inferred from its curve. Returns an error for unsupported curves.
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

// digestFor hashes data with h and returns the digest.
// Uses fixed-size stack arrays for the three supported hashes to avoid
// unnecessary heap allocation on the hot signing/verification path.
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
		panic(fmt.Sprintf("bestjwt: unsupported hash %v", h))
	}
}

// signEC is the shared implementation for SignES256/384/512.
func signEC(header, payload string, key *ecdsa.PrivateKey, h crypto.Hash) ([]byte, error) {
	digest := digestFor(h, header+"."+payload)
	r, s, err := ecdsa.Sign(rand.Reader, key, digest)
	if err != nil {
		return nil, fmt.Errorf("signEC: %w", err)
	}
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*byteLen)
	r.FillBytes(out[:byteLen])
	s.FillBytes(out[byteLen:])
	return out, nil
}

// ecdsaDERToRaw converts an ASN.1 DER-encoded ECDSA signature (as returned by
// [crypto.Signer]) to the fixed-width raw r||s format required by JWS.
// r and s are zero-padded to the curve's byte length via [big.Int.FillBytes].
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

// URLBase64 is a []byte that marshals to/from raw base64url in JSON.
type URLBase64 []byte

func (s URLBase64) String() string {
	return base64.RawURLEncoding.EncodeToString(s)
}

func (s URLBase64) MarshalJSON() ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(s)
	return json.Marshal(encoded)
}

func (s *URLBase64) UnmarshalJSON(data []byte) error {
	dst, err := base64.RawURLEncoding.AppendDecode([]byte{}, data)
	if err != nil {
		return fmt.Errorf("decode base64url signature: %w", err)
	}
	*s = dst
	return nil
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
