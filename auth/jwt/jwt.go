// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
)

// VerifiableJWT is the read-only interface implemented by [*JWT] and any
// custom JWT type. It exposes only the parsed header and payload - no mutation.
//
// Use [Verifier.VerifyJWT] to get a verified [*JWT], then call
// [RawJWT.UnmarshalClaims] to decode the payload. Or use [Decode] + [Verifier.Verify]
// for routing by header fields before verifying the signature.
type VerifiableJWT interface {
	GetProtected() []byte
	GetPayload() []byte
	GetSignature() []byte
	// GetHeader returns a copy of the decoded JOSE header fields.
	GetHeader() RFCHeader
}

// SignableJWT extends [VerifiableJWT] with the two hooks [Signer.SignJWT] needs.
// [*JWT] satisfies both [VerifiableJWT] and [SignableJWT].
//
// Custom JWT types implement SetHeader to merge the signer's standard
// fields (alg, kid, typ) with any custom header fields and store the
// encoded protected bytes. They implement SetSignature to store the result.
// No cryptographic knowledge is required - the [Signer] handles all of that.
type SignableJWT interface {
	VerifiableJWT
	// SetHeader encodes hdr as base64url and stores it as the protected
	// header. The signer reads the result via [GetProtected].
	SetHeader(hdr Header) error
	// SetSignature stores the computed signature bytes.
	SetSignature(sig []byte)
}

// RawJWT holds the three base64url-encoded segments of a compact JWT.
// Embed it in custom JWT types to get [RawJWT.GetProtected],
// [RawJWT.GetPayload], [RawJWT.GetSignature], and [RawJWT.SetClaims]
// for free. Custom types only need to add GetHeader to satisfy
// [VerifiableJWT], plus SetHeader and SetSignature for [SignableJWT].
type RawJWT struct {
	Protected []byte // base64url-encoded header
	Payload   []byte // base64url-encoded claims
	Signature []byte // decoded signature bytes
}

// GetProtected implements [VerifiableJWT].
func (raw *RawJWT) GetProtected() []byte { return raw.Protected }

// GetPayload implements [VerifiableJWT].
func (raw *RawJWT) GetPayload() []byte { return raw.Payload }

// GetSignature implements [VerifiableJWT].
func (raw *RawJWT) GetSignature() []byte { return raw.Signature }

// SetSignature implements [SignableJWT].
func (raw *RawJWT) SetSignature(sig []byte) { raw.Signature = sig }

// MarshalJSON encodes the RawJWT as a flattened JWS JSON object
// (RFC 7515 appendix A.7):
//
//	{"protected":"...","payload":"...","signature":"..."}
//
// Protected and Payload are already base64url strings and are written as-is.
// Signature is raw bytes and is base64url-encoded for the JSON output.
func (raw *RawJWT) MarshalJSON() ([]byte, error) {
	return json.Marshal(flatJWS{
		Protected: string(raw.Protected),
		Payload:   string(raw.Payload),
		Signature: base64.RawURLEncoding.EncodeToString(raw.Signature),
	})
}

// UnmarshalJSON decodes a flattened JWS JSON object into the RawJWT.
func (raw *RawJWT) UnmarshalJSON(data []byte) error {
	var v flatJWS
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	raw.Protected = []byte(v.Protected)
	raw.Payload = []byte(v.Payload)
	sig, err := base64.RawURLEncoding.DecodeString(v.Signature)
	if err != nil {
		return fmt.Errorf("signature base64: %w", err)
	}
	raw.Signature = sig
	return nil
}

// flatJWS is the flattened JWS JSON serialization (RFC 7515 appendix A.7).
type flatJWS struct {
	Protected string `json:"protected"`
	Payload   string `json:"payload"`
	Signature string `json:"signature"`
}

// SetClaims JSON-encodes claims and stores the result as the
// base64url-encoded payload. This is the payload counterpart of
// [SetHeader] -- use it when constructing a custom JWT type before signing.
func (raw *RawJWT) SetClaims(claims Claims) error {
	data, err := json.Marshal(claims)
	if err != nil {
		return fmt.Errorf("marshal claims: %w", err)
	}
	raw.Payload = []byte(base64.RawURLEncoding.EncodeToString(data))
	return nil
}

// UnmarshalHeader decodes the protected header into v.
//
// Use this to extract custom JOSE header fields beyond alg/kid/typ.
// v must satisfy [Header] - typically a pointer to a struct that embeds
// [RFCHeader] so the standard fields are captured alongside custom ones:
//
//	type DPoPHeader struct {
//	    jwt.RFCHeader
//	    JWK json.RawMessage `json:"jwk"`
//	}
//
//	raw, err := jwt.DecodeRaw(tokenStr)
//	var h DPoPHeader
//	if err := raw.UnmarshalHeader(&h); err != nil { /* ... */ }
//
// Promoted to [*JWT] via embedding, so it works after [Decode] too.
func (raw *RawJWT) UnmarshalHeader(h Header) error {
	data, err := base64.RawURLEncoding.AppendDecode([]byte{}, raw.Protected)
	if err != nil {
		return fmt.Errorf("header base64: %w: %w", ErrInvalidHeader, err)
	}
	if err := json.Unmarshal(data, h); err != nil {
		return fmt.Errorf("header json: %w: %w", ErrInvalidHeader, err)
	}
	return nil
}

// JWT is a decoded JSON Web Token.
//
// Technically this is a JWS (JSON Web Signature, RFC 7515) - the signed
// compact serialization that carries a header, payload, and signature.
// The term "JWT" (RFC 7519) strictly refers to the encoded string, but
// in practice everyone calls the decoded structure a JWT too, so we do
// the same.
//
// It holds only the parsed structure - header, raw base64url fields, and
// decoded signature bytes. It carries no Claims interface and no Verified flag;
// use [Verifier.VerifyJWT] or [Decode]+[Verifier.Verify] to authenticate the token
// and [RawJWT.UnmarshalClaims] to decode the payload into a typed struct.
//
// *JWT satisfies [VerifiableJWT] and [SignableJWT].
type JWT struct {
	RawJWT
	header jwsHeader
}

// GetHeader returns a copy of the decoded JOSE header fields.
// Implements [VerifiableJWT]. The returned value is a copy - mutations do not affect the JWT.
func (jws *JWT) GetHeader() RFCHeader { return jws.header.RFCHeader }

// Encode produces the compact JWT string (header.payload.signature).
// It is a convenience wrapper around the package-level [Encode] function.
func (jws *JWT) Encode() (string, error) { return Encode(jws) }

// SetHeader merges hdr into the internal header, encodes it as
// base64url, and stores the result. Implements [SignableJWT].
//
// Custom JWT types override this to merge hdr with their own additional
// header fields before encoding.
func (jws *JWT) SetHeader(hdr Header) error {
	jws.header.RFCHeader = *hdr.GetRFCHeader()
	data, err := json.Marshal(jws.header)
	if err != nil {
		return err
	}
	jws.Protected = []byte(base64.RawURLEncoding.EncodeToString(data))
	return nil
}

// SetTyp overrides the JOSE "typ" header field. The new value takes effect
// when [Signer.SignJWT] re-encodes the protected header. Use this after [New]
// to change the token type before signing:
//
//	tok, _ := jwt.New(claims)
//	tok.SetTyp(jwt.AccessTokenTyp)
//	signer.SignJWT(tok)
func (jws *JWT) SetTyp(typ string) { jws.header.Typ = typ }

// jwsHeader is an example of the pattern callers use when embedding [RFCHeader]
// in a custom JWT type. Embed [RFCHeader], and all its fields are promoted
// through the struct. To implement a custom JWT type, copy this struct and
// replace [RFCHeader] embedding with whatever custom header fields you need.
type jwsHeader struct {
	RFCHeader
}

// Header is satisfied for free by any struct that embeds [RFCHeader].
//
//	type DPoPHeader struct {
//	    jwt.RFCHeader
//	    JWK json.RawMessage `json:"jwk"`
//	}
//	// *DPoPHeader satisfies Header via promoted GetRFCHeader().
type Header interface {
	GetRFCHeader() *RFCHeader
}

// RFCHeader holds the standard JOSE header fields used in the JOSE protected header.
type RFCHeader struct {
	Alg string `json:"alg"`
	KID string `json:"kid,omitempty"`
	Typ string `json:"typ,omitempty"`
}

// GetRFCHeader implements [Header].
// Any struct embedding RFCHeader gets this method for free via promotion.
func (h *RFCHeader) GetRFCHeader() *RFCHeader { return h }

// DecodeRaw splits a compact JWT string into its three base64url segments
// and decodes the signature bytes, but does not parse the header JSON.
//
// Use this when you need to unmarshal the header into a custom struct
// with fields beyond alg/kid/typ. Call [RawJWT.UnmarshalHeader] to decode
// the protected header, or build a full [*JWT] with [Decode] instead.
func DecodeRaw(tokenStr string) (*RawJWT, error) {
	parts := strings.Split(tokenStr, ".")
	if len(parts) != 3 {
		if len(parts) == 1 && parts[0] == "" {
			parts = nil
		}
		return nil, fmt.Errorf("%w: expected 3 segments but got %d", ErrMalformedToken, len(parts))
	}

	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return nil, fmt.Errorf("signature base64: %w: %w", ErrSignatureInvalid, err)
	}

	return &RawJWT{
		Protected: []byte(parts[0]),
		Payload:   []byte(parts[1]),
		Signature: sig,
	}, nil
}

// Decode parses a compact JWT string (header.payload.signature) into a JWS.
//
// It does not unmarshal the claims payload - call [RawJWT.UnmarshalClaims] after
// [Verifier.VerifyJWT] or [Verifier.Verify] to populate a typed claims struct.
func Decode(tokenStr string) (*JWT, error) {
	raw, err := DecodeRaw(tokenStr)
	if err != nil {
		return nil, err
	}

	var jws JWT
	jws.RawJWT = *raw
	if err := jws.UnmarshalHeader(&jws.header); err != nil {
		return nil, err
	}

	return &jws, nil
}

// UnmarshalClaims decodes the payload into claims.
//
// Always call [Verifier.VerifyJWT] or [Decode]+[Verifier.Verify] before
// UnmarshalClaims - the signature must be authenticated before trusting the
// payload.
//
// Promoted to [*JWT] via embedding, so it works after [Decode] too.
func (raw *RawJWT) UnmarshalClaims(claims Claims) error {
	payload, err := base64.RawURLEncoding.AppendDecode([]byte{}, raw.Payload)
	if err != nil {
		return fmt.Errorf("payload base64: %w: %w", ErrInvalidPayload, err)
	}
	if err := json.Unmarshal(payload, claims); err != nil {
		return fmt.Errorf("payload json: %w: %w", ErrInvalidPayload, err)
	}
	return nil
}

// New creates an unsigned JWT from the provided claims.
//
// The "alg" and "kid" header fields are set automatically by [Signer.SignJWT]
// based on the key type and [PrivateKey.KID]. Call [Encode] or [JWT.Encode] to
// produce the compact JWT string after signing.
func New(claims Claims) (*JWT, error) {
	var jws JWT

	jws.header.RFCHeader = RFCHeader{
		// Alg and KID are set by Sign from the key type and PrivateKey.KID.
		Typ: "JWT",
	}
	headerJSON, err := json.Marshal(jws.header)
	if err != nil {
		return nil, fmt.Errorf("marshal header: %w", err)
	}
	jws.Protected = []byte(base64.RawURLEncoding.EncodeToString(headerJSON))

	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return nil, fmt.Errorf("marshal claims: %w", err)
	}
	jws.Payload = []byte(base64.RawURLEncoding.EncodeToString(claimsJSON))

	return &jws, nil
}

// NewAccessToken creates an unsigned JWT from claims with "typ" set to
// "at+jwt" per RFC 9068 §2.1. Sign with [Signer.SignJWT]:
//
//	tok, err := jwt.NewAccessToken(&claims)
//	if err := signer.SignJWT(tok); err != nil { /* ... */ }
//	token := tok.Encode()
//
// https://www.rfc-editor.org/rfc/rfc9068.html
func NewAccessToken(claims Claims) (*JWT, error) {
	jws, err := New(claims)
	if err != nil {
		return nil, err
	}
	jws.SetTyp(AccessTokenTyp)
	return jws, nil
}

// Encode produces the compact JWT string (header.payload.signature).
//
// Returns an error if the protected header's alg field is empty,
// indicating the token was never signed.
func Encode(jws VerifiableJWT) (string, error) {
	h := jws.GetHeader()
	if h.Alg == "" {
		return "", fmt.Errorf("encode: %w: alg is empty (unsigned token)", ErrInvalidHeader)
	}

	protected := jws.GetProtected()
	payload := jws.GetPayload()
	sig := base64.RawURLEncoding.EncodeToString(jws.GetSignature())
	out := make([]byte, 0, len(protected)+1+len(payload)+1+len(sig))
	out = append(out, protected...)
	out = append(out, '.')
	out = append(out, payload...)
	out = append(out, '.')
	out = append(out, sig...)
	return string(out), nil
}
