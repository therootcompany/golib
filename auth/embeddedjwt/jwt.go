// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package embeddedjwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
// that embeds StandardClaims satisfies Claims automatically via method promotion
// — no boilerplate required. Override Validate on the outer struct to add
// application-specific checks.
type Claims interface {
	Validate(params ValidateParams) ([]string, error)
}

// JWS is a decoded JSON Web Signature / JWT.
//
// Claims is stored as the [Claims] interface so that any embedded-struct type
// can be used without generics. Access the concrete type via the pointer you
// passed to [JWS.UnmarshalClaims].
//
// Typical usage:
//
//	jws, err := embeddedjwt.Decode(tokenString)
//	var claims AppClaims
//	err = jws.UnmarshalClaims(&claims)
//	jws.UnsafeVerify(pubKey)
//	errs, err := jws.Validate(params)
//	// claims.Email, claims.Roles, etc. are already populated
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
//	    embeddedjwt.StandardClaims
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
// It does not unmarshal the claims payload — call [JWS.UnmarshalClaims] after
// Decode to populate a typed claims struct. The signature is not verified;
// call [JWS.UnsafeVerify] before [JWS.Validate].
func Decode(tokenStr string) (*JWS, error) {
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

	if err := jws.Signature.UnmarshalJSON([]byte(sigEnc)); err != nil {
		return nil, fmt.Errorf("invalid signature encoding: %v", err)
	}

	return &jws, nil
}

// UnmarshalClaims decodes the JWT payload into v and stores v in jws.Claims.
//
// v must be a pointer to a concrete type that satisfies [Claims] (e.g.
// *AppClaims). After this call, the caller's variable is populated and
// jws.Validate will use it — no type assertion needed:
//
//	jws, _ := embeddedjwt.Decode(token)
//	var claims AppClaims
//	_ = jws.UnmarshalClaims(&claims)
//	jws.UnsafeVerify(pubKey)
//	jws.Validate(params)
//	// claims.Email, claims.Roles, etc. are already set
func (jws *JWS) UnmarshalClaims(v Claims) error {
	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return fmt.Errorf("invalid claims encoding: %v", err)
	}
	if err := json.Unmarshal(payload, v); err != nil {
		return fmt.Errorf("invalid claims JSON: %v", err)
	}
	jws.Claims = v
	return nil
}

// NewJWSFromClaims creates an unsigned JWS from the provided claims.
//
// kid identifies the signing key. The "alg" header field is set automatically
// when [JWS.Sign] is called. Call [JWS.Encode] to produce a compact JWT string
// after signing.
func NewJWSFromClaims(claims Claims, kid string) (*JWS, error) {
	var jws JWS

	jws.Header = StandardHeader{
		// Alg is set by Sign based on the key type.
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
// It sets the "alg" header field based on the public key type and re-encodes
// the protected header before signing, so the signed input is always consistent.
//
// Supported public key types (via Signer.Public()):
//   - *ecdsa.PublicKey → ES256 (ECDSA P-256, raw r||s)
//   - *rsa.PublicKey   → RS256 (PKCS#1 v1.5 + SHA-256)
//
// Because the parameter is [crypto.Signer] rather than a concrete key type,
// hardware-backed keys (HSM, OS keychain, etc.) work without modification.
func (jws *JWS) Sign(key crypto.Signer) ([]byte, error) {
	switch pub := key.Public().(type) {
	case *ecdsa.PublicKey:
		jws.Header.Alg = "ES256"
		headerJSON, _ := json.Marshal(jws.Header)
		jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

		hash := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
		// crypto.Signer returns ASN.1 DER for ECDSA; convert to raw r||s for JWS.
		derSig, err := key.Sign(rand.Reader, hash[:], crypto.SHA256)
		if err != nil {
			return nil, fmt.Errorf("Sign ES256: %w", err)
		}
		jws.Signature, err = ecdsaDERToRaw(derSig, pub.Curve)
		return jws.Signature, err

	case *rsa.PublicKey:
		jws.Header.Alg = "RS256"
		headerJSON, _ := json.Marshal(jws.Header)
		jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

		hash := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
		// crypto.Signer returns raw PKCS#1 v1.5 bytes for RSA; use directly.
		var err error
		jws.Signature, err = key.Sign(rand.Reader, hash[:], crypto.SHA256)
		return jws.Signature, err

	default:
		return nil, fmt.Errorf("Sign: unsupported public key type %T (supported: *ecdsa.PublicKey, *rsa.PublicKey)", key.Public())
	}
}

// Encode produces the compact JWT string (header.payload.signature).
func (jws JWS) Encode() string {
	sigEnc := base64.RawURLEncoding.EncodeToString(jws.Signature)
	return jws.Protected + "." + jws.Payload + "." + sigEnc
}

// UnsafeVerify checks the signature using the algorithm in the JWT header and
// sets jws.Verified on success. It only checks the signature — use
// [JWS.Validate] to check claim values.
//
// pub must be of the concrete type matching the header alg (e.g.
// *ecdsa.PublicKey for ES256). Callers can pass PublicJWK.Key directly
// without a type assertion.
//
// Currently supported: ES256, RS256.
func (jws *JWS) UnsafeVerify(pub Key) bool {
	signingInput := jws.Protected + "." + jws.Payload

	hash := sha256.Sum256([]byte(signingInput))

	switch jws.Header.Alg {
	case "ES256":
		k, ok := pub.(*ecdsa.PublicKey)
		if !ok || len(jws.Signature) != 64 {
			jws.Verified = false
			return false
		}
		r := new(big.Int).SetBytes(jws.Signature[:32])
		s := new(big.Int).SetBytes(jws.Signature[32:])
		jws.Verified = ecdsa.Verify(k, hash[:], r, s)
	case "RS256":
		k, ok := pub.(*rsa.PublicKey)
		if !ok {
			jws.Verified = false
			return false
		}
		jws.Verified = rsa.VerifyPKCS1v15(k, crypto.SHA256, hash[:], jws.Signature) == nil
	default:
		jws.Verified = false
	}
	return jws.Verified
}

// Validate sets params.Now if zero, then delegates to jws.Claims.Validate and
// additionally enforces that the signature was verified (unless params.IgnoreSig).
// Returns an error if [JWS.UnmarshalClaims] has not been called.
func (jws *JWS) Validate(params ValidateParams) ([]string, error) {
	if jws.Claims == nil {
		return []string{"claims not decoded: call UnmarshalClaims before Validate"}, fmt.Errorf("has errors")
	}

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
// This is called by [StandardClaims.Validate] and is exported so that
// custom claims types can call it from an overriding Validate method:
//
//	func (c AppClaims) Validate(params embeddedjwt.ValidateParams) ([]string, error) {
//	    errs, _ := embeddedjwt.ValidateStandardClaims(c.StandardClaims, params)
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

// --- Private key / signing helpers ---

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

// SignES256 computes an ES256 signature over header.payload.
// The signature is a fixed-width raw r||s value (not ASN.1 DER).
// r and s are zero-padded to the curve's byte length via [big.Int.FillBytes].
func SignES256(header, payload string, key *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("SignES256: %w", err)
	}
	byteLen := (key.Curve.Params().BitSize + 7) / 8
	out := make([]byte, 2*byteLen)
	r.FillBytes(out[:byteLen])
	s.FillBytes(out[byteLen:])
	return out, nil
}

// SignRS256 computes an RS256 (PKCS#1 v1.5 + SHA-256) signature over header.payload.
func SignRS256(header, payload string, key *rsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256([]byte(header + "." + payload))
	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, hash[:])
	if err != nil {
		return nil, fmt.Errorf("SignRS256: %w", err)
	}
	return sig, nil
}

// ecdsaDERToRaw converts an ASN.1 DER ECDSA signature (as returned by
// [crypto.Signer]) to the fixed-width r||s format required by JWS.
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

// EncodeToJWT appends a base64url-encoded signature to a signing input.
func EncodeToJWT(signingInput string, signature []byte) string {
	sigEnc := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + sigEnc
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
