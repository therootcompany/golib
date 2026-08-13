// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// SharedSecret is the symmetric-key counterpart to [PrivateKey].
//
// It holds a shared secret byte slice with JWKS metadata (KID, Use).
// [SharedSecret.Thumbprint] computes the RFC 7638 JWK Thumbprint
// (SHA-256 of the canonical key JSON). For HMAC keys the canonical form
// is {"k":"...","kty":"oct"} — note that KID is NOT included in the
// thumbprint per RFC 7638 §3.2.
//
// [SharedSecret.MarshalJSON] / [UnmarshalJSON] handle JWK wire format:
// {"k":"...","kty":"oct","kid":"...","use":"sig"}.
//
// Use [NewHMACSecret] to construct with auto-computed KID, [NewSharedSecret]
// for manual KID, [ParseSharedSecretJWK] to parse from JWK JSON, and
// [keyfile.LoadSharedSecretJWK] to load from file.
type SharedSecret struct {
	KID    string
	Use    string
	secret []byte
}

// NewHMACSecret generates a secure SharedSecret with sane defaults.
//
// The key is cryptographically random, 32 bytes (256-bit), hex-encoded,
// with JWK Thumbprint to optionally use as a Key ID.
func NewHMACSecret() (*SharedSecret, string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return nil, "", fmt.Errorf("NewHMACSecret: read random: %w", err)
	}
	secret := []byte(hex.EncodeToString(b))
	ss := &SharedSecret{secret: secret}
	thumb, err := ss.Thumbprint()
	if err != nil {
		return nil, "", fmt.Errorf("NewHMACSecret: thumbprint: %w", err)
	}
	return ss, thumb, nil
}

// NewSharedSecret creates a SharedSecret from raw bytes with optional
// public-facing Key ID.
//
// Requires at least 16 bytes. For randomly generated secrets, use
// [NewHMACSecret].
func NewSharedSecret(secret []byte, kid string) (*SharedSecret, error) {
	if len(secret) == 0 {
		return nil, fmt.Errorf("NewSharedSecret: %w", ErrNoSigningKey)
	}
	if len(secret) < 16 {
		return nil, fmt.Errorf("NewSharedSecret: %w", ErrKeyTooSmall)
	}
	return &SharedSecret{secret: secret, KID: kid}, nil
}

// KeyType returns the JWK "kty" string: "oct".
func (s SharedSecret) KeyType() string { return "oct" }

// Secret returns the raw secret bytes.
func (s SharedSecret) Secret() []byte { return s.secret }

// Thumbprint computes the RFC 7638 JWK Thumbprint for this key.
//
// The canonical JSON for "oct" keys is {"k":"...","kty":"oct"} —
// KID is excluded from the thumbprint per RFC 7638 §3.2.
// The result is base64url-encoded SHA-256.
//
// https://www.rfc-editor.org/rfc/rfc7638.html
func (s SharedSecret) Thumbprint() (string, error) {
	k := base64.RawURLEncoding.EncodeToString(s.secret)
	canonical, err := json.Marshal(struct {
		K   string `json:"k"`
		Kty string `json:"kty"`
	}{K: k, Kty: "oct"})
	if err != nil {
		return "", fmt.Errorf("thumbprint: marshal canonical JSON: %w", err)
	}
	sum := sha256.Sum256(canonical)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// MarshalJSON implements [json.Marshaler], encoding the secret as a JWK
// JSON object with the "k" field and "kty":"oct".
func (s SharedSecret) MarshalJSON() ([]byte, error) {
	k := base64.RawURLEncoding.EncodeToString(s.secret)
	return json.Marshal(sharedSecretJSON{
		K:   k,
		KID: s.KID,
		Kty: "oct",
		Use: s.Use,
	})
}

// UnmarshalJSON implements [json.Unmarshaler], parsing a JWK JSON object
// with "kty":"oct". The "k" field (base64url-encoded secret) is required
// and must be non-empty. If KID is empty, it is left unset.
func (s *SharedSecret) UnmarshalJSON(data []byte) error {
	var raw sharedSecretJSON
	if err := json.Unmarshal(data, &raw); err != nil {
		return fmt.Errorf("parse JWK: %w", err)
	}
	if raw.Kty != "oct" {
		return fmt.Errorf("SharedSecret: kty %q: %w", raw.Kty, ErrUnsupportedKeyType)
	}
	if raw.K == "" {
		return fmt.Errorf("parse JWK: missing k field: %w", ErrMissingKeyData)
	}
	secret, err := base64.RawURLEncoding.DecodeString(raw.K)
	if err != nil {
		return fmt.Errorf("parse JWK: decode k: %w", err)
	}
	s.secret = secret
	s.KID = raw.KID
	s.Use = raw.Use
	return nil
}

// ParseSharedSecretJWK parses a single JWK JSON object with "kty":"oct"
// into a [SharedSecret]. If the JWK has no "kid" field, the KID is
// left unset.
func ParseSharedSecretJWK(data []byte) (*SharedSecret, error) {
	var ss SharedSecret
	if err := ss.UnmarshalJSON(data); err != nil {
		return nil, err
	}
	return &ss, nil
}

type sharedSecretJSON struct {
	K   string `json:"k,omitempty"`
	KID string `json:"kid,omitempty"`
	Kty string `json:"kty"`
	Use string `json:"use,omitempty"`
}

// HMACSigner signs JWTs using HMAC with a shared secret.
//
// HMACSigner implements the symmetric-key signing counterpart to [Signer].
// It creates tokens with alg=HS256/HS384/HS512 and a shared secret key.
//
// Use [HMACSigner.Sign] or [HMACSigner.SignToString] to create tokens, then
// use [HMACSigner.Verifier] to verify them.
type HMACSigner struct {
	alg     crypto.Hash
	secret  *SharedSecret
	retired []*SharedSecret
}

var _ jwtsigner[*HMACVerifier] = (*HMACSigner)(nil)

// NewHMACSigner creates a HMACSigner that signs JWTs with the given
// algorithm and shared secret.
//
// The recommended minimum secret length is 32 bytes for HS256, 48 bytes
// for HS384, and 64 bytes for HS512. Shorter secrets (minimum 16 bytes)
// are accepted but weaken security.
//
// Retired secrets are accepted for verifying legacy tokens signed with
// older keys. They are passed through to the verifier.
//
// Example:
//
//	secret := []byte(os.Getenv("JWT_SECRET"))
//	key := jwt.NewSharedSecret([]byte(secret), "my-key")
//	signer, _ := jwt.NewHMACSigner(crypto.SHA256, key)
func NewHMACSigner(alg crypto.Hash, secret *SharedSecret, retired ...*SharedSecret) (*HMACSigner, error) {
	if secret == nil {
		return nil, fmt.Errorf("NewHMACSigner: %w", ErrNoSigningKey)
	}
	// Validate algorithm by attempting to create an HMAC hasher.
	if _, err := hmacSign(alg, secret.secret, nil); err != nil {
		return nil, fmt.Errorf("NewHMACSigner: key %q: %w", secret.KID, err)
	}
	// Validate retired secrets (length/nil checks are in NewSharedSecret).
	for i, rs := range retired {
		if rs == nil {
			return nil, fmt.Errorf("NewHMACSigner: retired[%d]: %w", i, ErrNoSigningKey)
		}
		if _, err := hmacSign(alg, rs.secret, nil); err != nil {
			return nil, fmt.Errorf("NewHMACSigner: retired[%d] key %q: %w", i, rs.KID, err)
		}
	}
	return &HMACSigner{
		alg:     alg,
		secret:  secret,
		retired: retired,
	}, nil
}

// Sign creates and signs a JWT from claims, returning the signed [*JWT].
//
// Use this when you need access to the signed JWT object (e.g., to inspect
// headers or read the raw signature). For the common case of producing a
// compact token string, use [HMACSigner.SignToString].
func (s *HMACSigner) Sign(claims Claims) (*JWT, error) {
	jws, err := New(claims)
	if err != nil {
		return nil, err
	}
	if err := s.SignJWT(jws); err != nil {
		return nil, err
	}
	return jws, nil
}

// SignToString creates and signs a JWT from claims and returns the compact
// token string (header.payload.signature).
//
// This is the most convenient form for the common case of signing and
// immediately transmitting a token.
func (s *HMACSigner) SignToString(claims Claims) (string, error) {
	jws, err := s.Sign(claims)
	if err != nil {
		return "", err
	}
	return Encode(jws)
}

// SignJWT signs a JWT in-place.
//
// Sets the alg header to the signer's algorithm. If the signing key has a
// KID set, it is written into the JWT header.
//
// Computes the HMAC signature over the protected.payload input.
func (s *HMACSigner) SignJWT(jws SignableJWT) error {
	if len(s.secret.secret) == 0 {
		return ErrNoSigningKey
	}

	hdr := jws.GetHeader()

	// Validate and set header algorithm.
	if hdr.Alg != "" && hdr.Alg != s.algorithm() {
		return ErrAlgConflict
	}
	hdr.Alg = s.algorithm()

	// Set KID from the signing key if present.
	if s.secret.KID != "" {
		hdr.KID = s.secret.KID
	}

	if err := jws.SetHeader(&hdr); err != nil {
		return err
	}

	input := signingInputBytes(jws.GetProtected(), jws.GetPayload())

	sig, err := hmacSign(s.alg, s.secret.secret, input)
	if err != nil {
		return err
	}

	jws.SetSignature(sig)
	return nil
}

// SignRaw signs an arbitrary protected header and payload, returning
// the result as a [*RawJWT] suitable for json.Marshal (flattened JWS)
// or Encode (compact serialization).
//
// Unlike [SignJWT], SignRaw does not set or validate the KID field —
// the caller controls it entirely. This supports protocols like ACME
// (RFC 8555) where kid is an account URL, or where kid must be absent
// (newAccount uses jwk instead).
//
// The alg field is always set from the signer's algorithm. If hdr
// already has a non-empty Alg that conflicts with the signer's
// algorithm, SignRaw returns an error.
//
// payload is the raw bytes to encode as the JWS payload. A nil payload
// produces an empty payload segment (used by ACME POST-as-GET).
func (s *HMACSigner) SignRaw(hdr Header, payload []byte) (*RawJWT, error) {
	if len(s.secret.secret) == 0 {
		return nil, ErrNoSigningKey
	}

	rfc := hdr.GetRFCHeader()

	// Validate and set header algorithm.
	if rfc.Alg != "" && rfc.Alg != s.algorithm() {
		return nil, ErrAlgConflict
	}
	rfc.Alg = s.algorithm()

	headerJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, err
	}

	protectedB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	var payloadB64 string
	if payload != nil {
		payloadB64 = base64.RawURLEncoding.EncodeToString(payload)
	}

	input := signingInputBytes([]byte(protectedB64), []byte(payloadB64))

	sig, err := hmacSign(s.alg, s.secret.secret, input)
	if err != nil {
		return nil, err
	}

	return &RawJWT{
		Protected: []byte(protectedB64),
		Payload:   []byte(payloadB64),
		Signature: sig,
	}, nil
}

// algorithm returns the JWS alg string for this algorithm (e.g. "HS256").
func (s *HMACSigner) algorithm() string {
	return hashToHMACAlg(s.alg)
}

// hmacSign computes HMAC of data with the given key and algorithm.
func hmacSign(alg crypto.Hash, key, data []byte) ([]byte, error) {
	h := crypto.Hash(alg)
	if !h.Available() {
		return nil, fmt.Errorf("algorithm %s: %w", hashToHMACAlg(h), ErrUnsupportedAlg)
	}
	mac := hmac.New(h.New, key)
	mac.Write(data)
	return mac.Sum(nil), nil
}

// hashToHMACAlg maps a crypto.Hash to its JWS HMAC algorithm string.
func hashToHMACAlg(h crypto.Hash) string {
	switch h {
	case crypto.SHA256:
		return "HS256"
	case crypto.SHA384:
		return "HS384"
	case crypto.SHA512:
		return "HS512"
	default:
		return fmt.Sprintf("unknown(%d)", h)
	}
}

// Verifier returns a new [*HMACVerifier] for verifying tokens signed by this signer.
//
// The verifier uses the same algorithm and secret as the signer.
func (s *HMACSigner) Verifier() *HMACVerifier {
	return &HMACVerifier{
		alg:     s.alg,
		secret:  s.secret,
		retired: s.retired,
	}
}

var _ jwtverifier = (*HMACVerifier)(nil)

// HMACVerifier verifies JWT signatures using HMAC with a shared secret.
//
// HMACVerifier is the symmetric-key counterpart to [Signer]. It holds
// a secret and an algorithm, matching what [HMACSigner] uses. Retired
// secrets are also included for verifying legacy tokens.
//
// HMACVerifier is immutable after construction - safe for concurrent use.
type HMACVerifier struct {
	alg     crypto.Hash
	secret  *SharedSecret
	retired []*SharedSecret
}

// NewHMACVerifier creates a HMACVerifier that verifies JWTs signed with
// the given algorithm and shared secret.
//
// The secret must match what was used to sign the tokens. A wrong secret
// will cause [HMACVerifier.Verify] to return [ErrSignatureInvalid].
//
// Retired secrets are accepted for verifying legacy tokens signed with
// older keys. They are tried after the active secret.
//
// Example:
//
//	secret := []byte(os.Getenv("JWT_SECRET"))
//	key := jwt.NewSharedSecret([]byte(secret), "my-key")
//	verifier, _ := jwt.NewHMACVerifier(crypto.SHA256, key)
func NewHMACVerifier(alg crypto.Hash, secret *SharedSecret, retired ...*SharedSecret) (*HMACVerifier, error) {
	if secret == nil {
		return nil, fmt.Errorf("NewHMACVerifier: %w", ErrNoVerificationKey)
	}
	// Validate algorithm by attempting to create an HMAC hasher.
	if _, err := hmacSign(alg, secret.secret, nil); err != nil {
		return nil, fmt.Errorf("NewHMACVerifier: key %q: %w", secret.KID, err)
	}
	// Validate retired secrets (length/nil checks are in NewSharedSecret).
	for i, rs := range retired {
		if rs == nil {
			return nil, fmt.Errorf("NewHMACVerifier: retired[%d]: %w", i, ErrNoVerificationKey)
		}
		if _, err := hmacSign(alg, rs.secret, nil); err != nil {
			return nil, fmt.Errorf("NewHMACVerifier: retired[%d] key %q: %w", i, rs.KID, err)
		}
	}
	return &HMACVerifier{
		alg:     alg,
		secret:  secret,
		retired: retired,
	}, nil
}

// Verify checks the signature of an already-decoded [*JWT].
//
// Key selection by KID:
//   - Token has a KID: only secrets matching that KID are tried.
//   - Token has no KID, or a secret has no KID: considered a match.
//   - Returns [ErrUnknownKID] if no secret matches the token's KID.
//
// The algorithm is fixed at construction time. Within matching secrets,
// the active secret is tried first, then retired secrets. The first
// successful verification wins.
//
// Returns nil on success, a descriptive error on failure. Claim values
// (iss, aud, exp, etc.) are NOT checked - call [Validator.Validate]
// on the unmarshalled claims after verifying.
//
// Use [VerifyJWT] to decode and verify in one step.
func (v *HMACVerifier) Verify(jws VerifiableJWT) error {
	h := jws.GetHeader()

	// Validate algorithm matches.
	if h.Alg != v.algorithm() {
		return fmt.Errorf("key %s vs header %q: %w", v.algorithm(), h.Alg, ErrAlgConflict)
	}

	signingInput := signingInputBytes(jws.GetProtected(), jws.GetPayload())
	sig := jws.GetSignature()

	// Try each secret, matching by KID (empty KID on either side is a match).
	var tried bool
	for _, ss := range v.allSecrets() {
		if h.KID != "" {
			if ss.KID != "" && h.KID != ss.KID {
				continue
			}
		}
		tried = true
		expectedSig, err := hmacSign(v.alg, ss.secret, signingInput)
		if err != nil {
			continue
		}
		if hmac.Equal(expectedSig, sig) {
			return nil
		}
	}

	if !tried {
		return fmt.Errorf("kid %q: %w", h.KID, ErrUnknownKID)
	}
	return ErrSignatureInvalid
}

// allSecrets returns the active secret followed by retired secrets.
func (v *HMACVerifier) allSecrets() []*SharedSecret {
	result := make([]*SharedSecret, 0, 1+len(v.retired))
	result = append(result, v.secret)
	result = append(result, v.retired...)
	return result
}

// VerifyJWT decodes tokenStr and verifies its signature, returning the parsed
// [*JWT] on success.
//
// Returns (nil, err) on any failure - the caller never receives an
// unauthenticated JWT. Claim values (iss, aud, exp, etc.) are NOT checked;
// call [Validator.Validate] on the unmarshalled claims after VerifyJWT:
//
//	jws, err := v.VerifyJWT(tokenStr)
//	if err != nil { /* bad sig, malformed token */ }
//	var claims jwt.TokenClaims
//	if err := jws.UnmarshalClaims(&claims); err != nil { /* ... */ }
//	if err := v.Validate(nil, &claims, time.Now()); err != nil { /* ... */ }
func (v *HMACVerifier) VerifyJWT(tokenStr string) (*JWT, error) {
	jws, err := Decode(tokenStr)
	if err != nil {
		return nil, err
	}
	if err := v.Verify(jws); err != nil {
		return nil, err
	}
	return jws, nil
}

// algorithm returns the JWS alg string for this verifier (e.g. "HS256").
func (v *HMACVerifier) algorithm() string {
	return hashToHMACAlg(v.alg)
}
