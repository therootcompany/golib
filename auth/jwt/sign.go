// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"crypto"
	"crypto/rand"
	"fmt"
	"sync/atomic"

	"github.com/therootcompany/golib/auth/jwt/internal/jwa"
	"github.com/therootcompany/golib/auth/jwt/jose"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// Signer manages one or more private signing keys and issues JWTs by
// round-robining across them. It is the issuing side of a JWT issuer -
// the party that signs tokens with a private key and publishes the
// corresponding public keys.
//
// Signer embeds [jwk.JWKs], so the JWKS endpoint response is just:
//
//	json.Marshal(&signer)
//
// Do not copy a Signer after first use - it contains an atomic counter.
type Signer struct {
	jwk.JWKs // Keys []jwk.PublicKey - promoted; marshals as {"keys":[...]}.
	// Note: Keys is exported because json.Marshal needs it for the JWKS
	// endpoint. Callers should not mutate the slice after construction.
	keys      []jwk.PrivateKey
	signerIdx atomic.Uint64
}

// NewSigner creates a Signer from the provided signing keys.
//
// NewSigner normalises each key:
//   - Alg: derived from the key type (ES256/ES384/ES512/RS256/EdDSA).
//     Returns an error if the caller set an incompatible Alg.
//   - Use: defaults to "sig" if empty.
//   - KID: auto-computed from the RFC 7638 thumbprint if empty.
//
// Returns an error if the slice is empty, any key has no Signer,
// the key type is unsupported, or a thumbprint cannot be computed.
//
// https://www.rfc-editor.org/rfc/rfc7638.html
// TODO allow for non-signing keys (for key rotation)
func NewSigner(keys []jwk.PrivateKey) (*Signer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("NewSigner: %w", jose.ErrNoSigningKey)
	}
	// Copy so the caller can't mutate after construction.
	ss := make([]jwk.PrivateKey, len(keys))
	copy(ss, keys)
	for i := range ss {
		if ss[i].Signer == nil {
			return nil, fmt.Errorf("NewSigner: key[%d] kid %q: %w", i, ss[i].KID, jose.ErrNoSigningKey)
		}

		// Derive algorithm from key type; validate caller's Alg if already set.
		alg, _, _, err := jwa.SigningParams(ss[i].Signer)
		if err != nil {
			return nil, fmt.Errorf("NewSigner: key[%d]: %w", i, err)
		}
		if ss[i].Alg != "" && ss[i].Alg != alg {
			return nil, fmt.Errorf("NewSigner: key[%d] alg %q expected %s: %w", i, ss[i].Alg, alg, jose.ErrAlgConflict)
		}
		ss[i].Alg = alg

		// Default Use to "sig" for signing keys.
		if ss[i].Use == "" {
			ss[i].Use = "sig"
		}
		// TODO fail if not sig

		// Auto-compute KID from thumbprint if empty.
		if ss[i].KID == "" {
			thumb, err := ss[i].Thumbprint()
			if err != nil {
				return nil, fmt.Errorf("NewSigner: compute thumbprint for key[%d]: %w", i, err)
			}
			ss[i].KID = thumb
		}
	}

	// TODO use slice rather than map, allow "none" or IgnoreKID
	pubs := make([]jwk.PublicKey, len(ss))
	for i := range ss {
		pub, err := ss[i].PublicKey()
		if err != nil {
			return nil, fmt.Errorf("NewSigner: key[%d] kid %q: %w", i, ss[i].KID, err)
		}
		pubs[i] = *pub
	}
	return &Signer{
		JWKs: jwk.JWKs{Keys: pubs},
		keys: ss,
	}, nil
}

// SignJWS signs jws in-place using the next signing key in round-robin order.
//
// The KID and alg header fields are set automatically from the selected key.
// Use this when you need the full signed JWS for further processing
// (e.g., inspecting headers before encoding). For the common one-step cases,
// prefer [Signer.Sign] or [Signer.SignToString].
func (s *Signer) SignJWS(jws SignableJWS) error {
	// Round-robin with CAS wrap: keeps the counter bounded to [0, n)
	// so it never approaches uint64 overflow.
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
	pk := &s.keys[idx]

	if pk.Signer == nil {
		return fmt.Errorf("kid %q: %w", pk.KID, jose.ErrNoSigningKey)
	}
	hdr := jws.GetHeader()
	switch {
	case hdr.KID == "":
		hdr.KID = pk.KID
	case hdr.KID != pk.KID:
		return fmt.Errorf("header kid %q vs key kid %q: %w", hdr.KID, pk.KID, jose.ErrKIDConflict)
	}

	alg, hash, ecKeySize, err := jwa.SigningParams(pk.Signer)
	if err != nil {
		return err
	}

	// Validate and set header algorithm.
	if hdr.Alg != "" && hdr.Alg != alg {
		return fmt.Errorf("key %s vs header %q: %w", alg, hdr.Alg, jose.ErrAlgConflict)
	}
	hdr.Alg = alg

	protected, err := jws.MarshalHeader(hdr)
	if err != nil {
		return err
	}

	input := signingInputBytes(protected, jws.GetPayload())

	// Sign: pre-hash for EC/RSA, or sign raw for Ed25519.
	var sig []byte
	if hash != 0 {
		var digest []byte
		digest, err = digestFor(hash, input)
		if err != nil {
			return err
		}
		sig, err = pk.Signer.Sign(rand.Reader, digest, hash)
	} else {
		sig, err = pk.Signer.Sign(rand.Reader, input, crypto.Hash(0))
	}
	if err != nil {
		return fmt.Errorf("sign %s: %w", alg, err)
	}

	// ECDSA: crypto.Signer returns ASN.1 DER, but JWS (RFC 7515 §A.3)
	// requires IEEE P1363 format (raw r||s concatenation).
	if ecKeySize > 0 {
		sig, err = ecdsaDERToP1363(sig, ecKeySize)
		if err != nil {
			return err
		}
	}

	jws.SetSignature(sig)
	return nil
}

// Sign creates a JWS from claims, signs it with the next signing key,
// and returns the signed JWS.
//
// Use this when you need access to the signed JWS object (e.g., to inspect
// headers or read the raw signature). For the common case of producing a
// compact token string, use [Signer.SignToString].
func (s *Signer) Sign(claims Claims) (*JWS, error) {
	jws, err := New(claims)
	if err != nil {
		return nil, err
	}
	if err := s.SignJWS(jws); err != nil {
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
	return Encode(jws), nil
}

// Verifier returns a new [*Verifier] containing the public keys of all signing keys.
//
// Use this to construct a Verifier for verifying tokens signed by this Signer.
// For key rotation, combine with old public keys:
//
//	iss := jwt.New(append(signer.Keys, oldKeys...))
func (s *Signer) Verifier() *Verifier {
	// NewSigner already validated keys — duplicates cannot occur here.
	v, _ := NewVerifier(s.Keys)
	return v
}
