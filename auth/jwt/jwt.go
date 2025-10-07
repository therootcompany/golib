// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"math/big"
	"slices"
	"strings"
	"time"
)

type Keypair struct {
	Thumbprint string
	PrivateKey *ecdsa.PrivateKey
}

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	D   string `json:"d"`
	X   string `json:"x"`
	Y   string `json:"y"`
}

type JWT string

func (jwt JWT) Split() (string, string, string, error) {
	parts := strings.Split(string(jwt), ".")
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("invalid JWT format")
	}

	rawHeader, rawPayload, rawSig := parts[0], parts[1], parts[2]
	return rawHeader, rawPayload, rawSig, nil
}

func (jwt JWT) Decode() (JWS, error) {
	h64, p64, s64, err := jwt.Split()
	if err != nil {
		return JWS{}, err
	}

	var jws JWS
	var sigEnc string
	jws.Protected, jws.Payload, sigEnc = h64, p64, s64

	header, err := base64.RawURLEncoding.DecodeString(jws.Protected)
	if err != nil {
		return jws, fmt.Errorf("invalid header encoding: %v", err)
	}
	if err := json.Unmarshal(header, &jws.Header); err != nil {
		return jws, fmt.Errorf("invalid header JSON: %v", err)
	}

	payload, err := base64.RawURLEncoding.DecodeString(jws.Payload)
	if err != nil {
		return jws, fmt.Errorf("invalid claims encoding: %v", err)
	}
	if err := json.Unmarshal(payload, &jws.Claims); err != nil {
		return jws, fmt.Errorf("invalid claims JSON: %v", err)
	}

	if err := jws.Signature.UnmarshalJSON([]byte(sigEnc)); err != nil {
		return jws, fmt.Errorf("invalid signature encoding: %v", err)
	}

	return jws, nil
}

type JWS struct {
	Protected string    `json:"-"` // base64
	Header    MyHeader  `json:"headers"`
	Payload   string    `json:"-"` // base64
	Claims    MyClaims  `json:"claims"`
	Signature URLBase64 `json:"signature"`
	Verified  bool      `json:"-"`
}

type MyHeader struct {
	StandardHeader
}

type StandardHeader struct {
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	Typ string `json:"typ"`
}

type MyClaims struct {
	StandardClaims
	Email      string   `json:"email"`
	EmployeeID string   `json:"employee_id"`
	FamilyName string   `json:"family_name"`
	GivenName  string   `json:"given_name"`
	Roles      []string `json:"roles"`
}

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

func NewJWS(email, employeeID, issuer, thumbprint string, roles []string) (JWS, error) {
	var jws JWS

	jws.Header.StandardHeader = StandardHeader{
		Alg: "ES256",
		Kid: thumbprint,
		Typ: "JWT",
	}
	headerJSON, _ := json.Marshal(jws.Header)
	jws.Protected = base64.RawURLEncoding.EncodeToString(headerJSON)

	now := time.Now().Unix()
	jtiBytes := make([]byte, 16)
	if _, err := rand.Read(jtiBytes); err != nil {
		return JWS{}, fmt.Errorf("failed to generate Jti: %v", err)
	}
	jti := base64.RawURLEncoding.EncodeToString(jtiBytes)
	emailName := strings.Split(email, "@")[0]

	jws.Claims = MyClaims{
		StandardClaims: StandardClaims{
			AuthTime: now,
			Exp:      now + 15*60*37, // TODO remove
			Iat:      now,
			Iss:      issuer,
			Jti:      jti,
			Sub:      email,
			Amr:      []string{"pwd"},
		},
		Email:      email,
		EmployeeID: employeeID,
		FamilyName: "McTestface",
		GivenName:  strings.ToUpper(emailName),
		Roles:      roles,
	}
	claimsJSON, _ := json.Marshal(jws.Claims)
	jws.Payload = base64.RawURLEncoding.EncodeToString(claimsJSON)

	return jws, nil
}

func (jws *JWS) Sign(key *ecdsa.PrivateKey) ([]byte, error) {
	var err error
	jws.Signature, err = SignJWS(jws.Protected, jws.Payload, key)
	return jws.Signature, err
}

// UnsafeVerify only checks the signature, use Validate to check all values
func (jws *JWS) UnsafeVerify(pub *ecdsa.PublicKey) bool {
	hash := sha256.Sum256([]byte(jws.Protected + "." + jws.Payload))
	n := len(jws.Signature)
	if n != 64 {
		// return fmt.Errorf("expected a 64-byte signature consisting of two 32-byte r and s components, but got %d instead (perhaps ASN.1 or other format)", n)
		return false
	}

	r := new(big.Int).SetBytes(jws.Signature[:32])
	s := new(big.Int).SetBytes(jws.Signature[32:])

	jws.Verified = ecdsa.Verify(pub, hash[:], r, s)
	return jws.Verified
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

// Validate checks common JWS fields and issuer, collecting all errors.
func (jws *JWS) Validate(params ValidateParams) ([]string, error) {
	var errs []string

	if params.Now.IsZero() {
		params.Now = time.Now()
	}

	// Required to exist and match
	if len(params.Iss) > 0 || !params.IgnoreIss {
		if len(jws.Claims.Iss) == 0 {
			errs = append(errs, ("missing or malformed 'iss' (token issuer, identifier for public key)"))
		} else if jws.Claims.Iss != params.Iss {
			errs = append(errs, fmt.Sprintf("'iss' (token issuer) mismatch: got %s, expected %s", jws.Claims.Iss, params.Iss))
		}
	}

	// Required to exist, optional match
	if len(jws.Claims.Sub) == 0 {
		if !params.IgnoreSub {
			errs = append(errs, ("missing or malformed 'sub' (subject, typically pairwise user id)"))
		}
	} else if len(params.Sub) > 0 {
		if params.Sub != jws.Claims.Sub {
			errs = append(errs, fmt.Sprintf("'sub' (subject, typically pairwise user id) mismatch: got %s, expected %s", jws.Claims.Sub, params.Sub))
		}
	}

	// Required to exist and match
	if len(params.Aud) > 0 || !params.IgnoreAud {
		if len(jws.Claims.Aud) == 0 {
			errs = append(errs, ("missing or malformed 'aud' (audience receiving token)"))
		} else if jws.Claims.Aud != params.Aud {
			errs = append(errs, fmt.Sprintf("'aud' (audience receiving token) mismatch: got %s, expected %s", jws.Claims.Aud, params.Aud))
		}
	}

	// Required to exist and not be in the past
	if !params.IgnoreExp {
		if jws.Claims.Exp <= 0 {
			errs = append(errs, ("missing or malformed 'exp' (expiration date in seconds)"))
		} else if jws.Claims.Exp < params.Now.Unix() {
			duration := time.Since(time.Unix(jws.Claims.Exp, 0))
			expTime := time.Unix(jws.Claims.Exp, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("token expired %s ago (%s)", formatDuration(duration), expTime))
		}
	}

	// Required to exist and not be in the future
	if !params.IgnoreIat {
		if jws.Claims.Iat <= 0 {
			errs = append(errs, ("missing or malformed 'iat' (issued at, when token was signed)"))
		} else if jws.Claims.Iat > params.Now.Unix() {
			duration := time.Unix(jws.Claims.Iat, 0).Sub(params.Now)
			iatTime := time.Unix(jws.Claims.Iat, 0).Format("2006-01-02 15:04:05 MST")
			errs = append(errs, fmt.Sprintf("'iat' (issued at, when token was signed) is %s in the future (%s)", formatDuration(duration), iatTime))
		}
	}

	// Should exist, in the past, with optional max age
	if params.MaxAge > 0 || !params.IgnoreAuthTime {
		if jws.Claims.AuthTime == 0 {
			errs = append(errs, ("missing or malformed 'auth_time' (time of real-world user authentication, in seconds)"))
		} else {
			authTime := time.Unix(jws.Claims.AuthTime, 0)
			authTimeStr := authTime.Format("2006-01-02 15:04:05 MST")
			age := params.Now.Sub(authTime)
			diff := age - params.MaxAge
			if jws.Claims.AuthTime > params.Now.Unix() {
				fromNow := time.Unix(jws.Claims.AuthTime, 0).Sub(params.Now)
				authTimeStr := time.Unix(jws.Claims.AuthTime, 0).Format("2006-01-02 15:04:05 MST")
				errs = append(errs, fmt.Sprintf(
					"'auth_time' (time of real-world user authentication) of %s is %s in the future (server time %s)",
					authTimeStr, formatDuration(fromNow), params.Now.Format("2006-01-02 15:04:05 MST")),
				)
			} else if age > params.MaxAge {
				errs = append(errs, fmt.Sprintf(
					"'auth_time' (time of real-world user authentication) of %s is %s old, which exceeds the max age of %s (%ds) by %s",
					authTimeStr, formatDuration(age), formatDuration(params.MaxAge), params.MaxAge/time.Second, formatDuration(diff)),
				)
			}
		}
	}

	// Optional
	if params.Jti != jws.Claims.Jti {
		if len(params.Jti) > 0 {
			errs = append(errs, fmt.Sprintf("'jti' (jwt id) mismatch: got %s, expected %s", jws.Claims.Jti, params.Jti))
		} else if !params.IgnoreJti {
			errs = append(errs, fmt.Sprintf("unchecked 'jti' (jwt id): %s", jws.Claims.Jti))
		}
	}

	// Optional
	if params.Nonce != jws.Claims.Nonce {
		if len(params.Nonce) > 0 {
			errs = append(errs, fmt.Sprintf("'nonce' (one-time random salt, as string) mismatch: got %s, expected %s", jws.Claims.Nonce, params.Nonce))
		} else if !params.IgnoreNonce {
			errs = append(errs, fmt.Sprintf("unchecked 'nonce' (one-time random salt): %s", jws.Claims.Nonce))
		}
	}

	// Acr check not implemented because the use case is not yet clear

	// Should exist, optional match
	if !params.IgnoreAmr {
		if len(jws.Claims.Amr) == 0 {
			errs = append(errs, ("missing or malformed 'amr' (authorization methods, as json list)"))
		} else {
			if len(params.RequiredAmrs) > 0 {
				for _, required := range params.RequiredAmrs {
					if !slices.Contains(jws.Claims.Amr, required) {
						errs = append(errs, fmt.Sprintf("missing required '%s' from 'amr' (authorization methods, as json list)", required))
					}
				}
			}

			// TODO specify multiple amrs in a tiered list (must have at least one from each list)
			// count := 0
			// if len(params.AcceptableAmrs) > 0 {
			// 	for _, amr := range jws.Claims.Amr {
			// 		if slices.Contains(params.AcceptableAmrs, amr) {
			// 			count += 1
			// 		}
			// 	}
			// }
		}
	}

	// Optional, should match if exists
	if params.Azp != jws.Claims.Azp {
		if len(params.Azp) > 0 {
			errs = append(errs, ("missing or malformed 'azp' (authorized party which presents token)"))
		} else if !params.IgnoreAzp {
			errs = append(errs, fmt.Sprintf("'azp' mismatch (authorized party which presents token): got %s, expected %s", jws.Claims.Azp, params.Azp))
		}
	}

	// Must be checked
	if !params.IgnoreSig {
		if !jws.Verified {
			errs = append(errs, ("signature was not checked"))
		}
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

func SignJWS(header, payload string, key *ecdsa.PrivateKey) ([]byte, error) {
	hash := sha256.Sum256([]byte(header + "." + payload))
	r, s, err := ecdsa.Sign(rand.Reader, key, hash[:])
	if err != nil {
		return nil, fmt.Errorf("failed to sign: %v", err)
	}
	return append(r.Bytes(), s.Bytes()...), nil
}

func (jws JWS) Encode() string {
	sigEnc := base64.RawURLEncoding.EncodeToString(jws.Signature)
	return jws.Protected + "." + jws.Payload + "." + sigEnc
}

func EncodeToJWT(signingInput string, signature []byte) string {
	sigEnc := base64.RawURLEncoding.EncodeToString(signature)
	return signingInput + "." + sigEnc
}

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

// URLBase64 unmarshals to bytes and marshals to a raw url base64 string
type URLBase64 []byte

func (s URLBase64) String() string {
	encoded := base64.RawURLEncoding.EncodeToString(s)
	return encoded
}

// MarshalJSON implements JSON marshaling to URL-safe base64.
func (s URLBase64) MarshalJSON() ([]byte, error) {
	encoded := base64.RawURLEncoding.EncodeToString(s)
	return json.Marshal(encoded)
}

// UnmarshalJSON implements JSON unmarshaling from URL-safe base64.
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
