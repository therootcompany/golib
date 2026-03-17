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
	"encoding/base64"
	"encoding/json"
	"fmt"
	"sync/atomic"
)

// Signer manages one or more private signing keys and issues JWTs by
// round-robining across them. It is the issuing side of a JWT issuer -
// the party that signs tokens with a private key and publishes the
// corresponding public keys.
//
// Signer has [WellKnownJWKs], so the JWKS endpoint response is just:
//
//	json.Marshal(&signer.WellKnownJWKs)
//
// The embedded WellKnownJWKs includes both the active signing keys' public keys
// and any RetiredKeys passed to [NewSigner]. Retired keys appear in the
// JWKS endpoint so that relying parties can still verify tokens signed
// before rotation, but they are never used for signing.
//
// Do not copy a Signer after first use - it contains an atomic counter.
type Signer struct {
	WellKnownJWKs // Keys []PublicKey - promoted; marshals as {"keys":[...]}.
	// Note: Keys is exported because json.Marshal needs it for the JWKS
	// endpoint. Callers should not mutate the slice after construction.
	keys      []PrivateKey
	signerIdx atomic.Uint64
}

// NewSigner creates a Signer from the provided signing keys.
//
// NewSigner normalises each key:
//   - Alg: derived from the key type (ES256/ES384/ES512/RS256/EdDSA).
//     Returns an error if the caller set an incompatible Alg.
//   - Use: defaults to "sig" if empty; returns an error if set to anything else.
//   - KID: auto-computed from the RFC 7638 thumbprint if empty.
//
// retiredKeys are public keys that appear in the JWKS endpoint for
// verification by relying parties but are no longer used for signing.
// This supports graceful key rotation: retire old keys so tokens signed
// before the rotation remain verifiable.
//
// Returns an error if the slice is empty, any key has no Signer,
// the key type is unsupported, or a thumbprint cannot be computed.
//
// https://www.rfc-editor.org/rfc/rfc7638.html
func NewSigner(keys []*PrivateKey, retiredKeys ...PublicKey) (*Signer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("NewSigner: %w", ErrNoSigningKey)
	}
	// Copy so the caller can't mutate after construction.
	ss := make([]PrivateKey, len(keys))
	for i, k := range keys {
		if k == nil || k.privKey == nil {
			return nil, fmt.Errorf("NewSigner: key[%d]: %w", i, ErrNoSigningKey)
		}
		ss[i] = *k

		// Derive algorithm from key type; validate caller's Alg if already set.
		alg, _, _, err := signingParams(ss[i].privKey)
		if err != nil {
			return nil, fmt.Errorf("NewSigner: key[%d]: %w", i, err)
		}
		if ss[i].Alg != "" && ss[i].Alg != alg {
			return nil, fmt.Errorf("NewSigner: key[%d] alg %q expected %s: %w", i, ss[i].Alg, alg, ErrAlgConflict)
		}
		ss[i].Alg = alg

		// Default Use to "sig" for signing keys; reject anything else.
		if ss[i].Use == "" {
			ss[i].Use = "sig"
		} else if ss[i].Use != "sig" {
			return nil, fmt.Errorf("NewSigner: key[%d] kid %q: use %q, want \"sig\"", i, ss[i].KID, ss[i].Use)
		}

		// Auto-compute KID from thumbprint if empty.
		if ss[i].KID == "" {
			pub, err := ss[i].PublicKey()
			if err != nil {
				return nil, fmt.Errorf("NewSigner: derive public key for key[%d]: %w", i, err)
			}
			thumb, err := pub.Thumbprint()
			if err != nil {
				return nil, fmt.Errorf("NewSigner: compute thumbprint for key[%d]: %w", i, err)
			}
			ss[i].KID = thumb
		}
	}

	pubs := make([]PublicKey, len(ss), len(ss)+len(retiredKeys))
	for i := range ss {
		pub, err := ss[i].PublicKey()
		if err != nil {
			return nil, fmt.Errorf("NewSigner: key[%d] kid %q: %w", i, ss[i].KID, err)
		}
		pubs[i] = *pub
	}

	// Validate each key by performing a test sign+verify round-trip.
	// This catches bad keys at construction rather than first use.
	for i := range ss {
		if err := validateSigningKey(&ss[i], &pubs[i]); err != nil {
			return nil, fmt.Errorf("NewSigner: key[%d] kid %q: %w", i, ss[i].KID, err)
		}
	}

	// Append retired keys so they appear in the JWKS endpoint but are
	// never selected for signing.
	pubs = append(pubs, retiredKeys...)
	return &Signer{
		WellKnownJWKs: WellKnownJWKs{Keys: pubs},
		keys:          ss,
	}, nil
}

// nextKey returns the next signing key in round-robin order.
func (s *Signer) nextKey() *PrivateKey {
	n := uint64(len(s.keys))
	var idx uint64
	for {
		cur := s.signerIdx.Load()
		next := (cur + 1) % n
		if s.signerIdx.CompareAndSwap(cur, next) {
			idx = cur
			break
		}
	}
	return &s.keys[idx]
}

// SignJWT signs jws in-place.
//
// Key selection: if the header already has a KID, the signer uses the key
// with that KID (returning [ErrUnknownKID] if none match). Otherwise the
// next key in round-robin order is selected and its KID is written into
// the header.
//
// The alg header field is set automatically from the selected key.
//
// Use this when you need the full signed JWT for further processing
// (e.g., inspecting headers before encoding). For the common one-step cases,
// prefer [Signer.Sign] or [Signer.SignToString].
func (s *Signer) SignJWT(jws SignableJWT) error {
	hdr := jws.GetHeader()

	var pk *PrivateKey
	if hdr.KID != "" {
		for i := range s.keys {
			if s.keys[i].KID == hdr.KID {
				pk = &s.keys[i]
				break
			}
		}
		if pk == nil {
			return fmt.Errorf("kid %q: %w", hdr.KID, ErrUnknownKID)
		}
	} else {
		pk = s.nextKey()
		hdr.KID = pk.KID
	}
	if pk.privKey == nil {
		return fmt.Errorf("kid %q: %w", pk.KID, ErrNoSigningKey)
	}

	alg, hash, ecKeySize, err := signingParams(pk.privKey)
	if err != nil {
		return err
	}

	// Validate and set header algorithm.
	if hdr.Alg != "" && hdr.Alg != alg {
		return fmt.Errorf("key %s vs header %q: %w", alg, hdr.Alg, ErrAlgConflict)
	}
	hdr.Alg = alg

	if err := jws.SetHeader(&hdr); err != nil {
		return err
	}

	input := signingInputBytes(jws.GetProtected(), jws.GetPayload())

	sig, err := signBytes(pk.privKey, alg, hash, ecKeySize, input)
	if err != nil {
		return err
	}

	jws.SetSignature(sig)
	return nil
}

// SignRaw signs an arbitrary protected header and payload, returning
// the result as a [*RawJWT] suitable for [json.Marshal] (flattened JWS)
// or [Encode] (compact serialization).
//
// Unlike [Signer.SignJWT], SignRaw does not set or validate the KID
// field -- the caller controls it entirely. This supports protocols
// like ACME (RFC 8555) where the kid is an account URL, or where kid
// must be absent (newAccount uses jwk instead).
//
// The alg field is always set from the key type. If hdr already has a
// non-empty Alg that conflicts with the key, SignRaw returns an error.
//
// payload is the raw bytes to encode as the JWS payload. A nil payload
// produces an empty payload segment (used by ACME POST-as-GET).
func (s *Signer) SignRaw(hdr Header, payload []byte) (*RawJWT, error) {
	pk := s.nextKey()
	if pk.privKey == nil {
		return nil, fmt.Errorf("kid %q: %w", pk.KID, ErrNoSigningKey)
	}

	rfc := hdr.GetRFCHeader()

	alg, hash, ecKeySize, err := signingParams(pk.privKey)
	if err != nil {
		return nil, err
	}
	if rfc.Alg != "" && rfc.Alg != alg {
		return nil, fmt.Errorf("key %s vs header %q: %w", alg, rfc.Alg, ErrAlgConflict)
	}
	rfc.Alg = alg

	headerJSON, err := json.Marshal(hdr)
	if err != nil {
		return nil, fmt.Errorf("marshal header: %w", err)
	}

	protectedB64 := base64.RawURLEncoding.EncodeToString(headerJSON)
	payloadB64 := base64.RawURLEncoding.EncodeToString(payload)

	input := signingInputBytes([]byte(protectedB64), []byte(payloadB64))

	sig, err := signBytes(pk.privKey, alg, hash, ecKeySize, input)
	if err != nil {
		return nil, err
	}

	return &RawJWT{
		Protected: []byte(protectedB64),
		Payload:   []byte(payloadB64),
		Signature: sig,
	}, nil
}

// Sign creates a JWT from claims, signs it with the next signing key,
// and returns the signed JWT.
//
// Use this when you need access to the signed JWT object (e.g., to inspect
// headers or read the raw signature). For the common case of producing a
// compact token string, use [Signer.SignToString].
func (s *Signer) Sign(claims Claims) (*JWT, error) {
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
// immediately transmitting a token. The caller is responsible for setting
// the "iss" field in claims if issuer identification is needed.
func (s *Signer) SignToString(claims Claims) (string, error) {
	jws, err := s.Sign(claims)
	if err != nil {
		return "", err
	}
	return Encode(jws)
}

// Verifier returns a new [*Verifier] containing the public keys of all
// signing keys plus any retired keys passed to [NewSigner].
//
// Panics if NewVerifier fails, which indicates an invariant violation
// since [NewSigner] already validated the keys.
func (s *Signer) Verifier() *Verifier {
	v, err := NewVerifier(s.Keys)
	if err != nil {
		panic(fmt.Sprintf("jwt: Signer.Verifier: NewVerifier failed on previously validated keys: %v", err))
	}
	return v
}

// signBytes signs input using the given crypto.Signer with the appropriate
// hash and ECDSA DER-to-P1363 conversion. It handles pre-hashing for EC/RSA
// and raw signing for Ed25519.
func signBytes(signer crypto.Signer, alg string, hash crypto.Hash, ecKeySize int, input []byte) ([]byte, error) {
	var sig []byte
	var err error
	if hash != 0 {
		digest, derr := digestFor(hash, input)
		if derr != nil {
			return nil, derr
		}
		sig, err = signer.Sign(nil, digest, hash)
	} else {
		sig, err = signer.Sign(nil, input, crypto.Hash(0))
	}
	if err != nil {
		return nil, fmt.Errorf("sign %s: %w", alg, err)
	}

	// ECDSA: crypto.Signer returns ASN.1 DER, but JWS (RFC 7515 §A.3)
	// requires IEEE P1363 format (raw r||s concatenation).
	if ecKeySize > 0 {
		sig, err = ecdsaDERToP1363(sig, ecKeySize)
		if err != nil {
			return nil, err
		}
	}
	return sig, nil
}

// validateSigningKey performs a test sign+verify round-trip to catch bad
// keys at construction time rather than on first use.
func validateSigningKey(pk *PrivateKey, pub *PublicKey) error {
	alg, hash, ecKeySize, err := signingParams(pk.privKey)
	if err != nil {
		return err
	}

	testInput := []byte("jwt-key-validation")

	sig, err := signBytes(pk.privKey, alg, hash, ecKeySize, testInput)
	if err != nil {
		return fmt.Errorf("test sign: %w", err)
	}

	// Verify against the public key.
	h := RFCHeader{Alg: alg, KID: pk.KID}
	if err := verifyOneKey(h, pub.Key, testInput, sig); err != nil {
		return fmt.Errorf("test verify: %w", err)
	}
	return nil
}
