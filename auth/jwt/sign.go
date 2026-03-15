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
	"io"
	"sync/atomic"
)

// Signer manages one or more private signing keys and issues JWTs by
// round-robining across them. It is the issuing side of a JWT issuer -
// the party that signs tokens with a private key and publishes the
// corresponding public keys.
//
// Signer embeds [JWKs], so the JWKS endpoint response is just:
//
//	json.Marshal(&signer)
//
// The embedded JWKs includes both the active signing keys' public keys
// and any RetiredKeys passed to [NewSigner]. Retired keys appear in the
// JWKS endpoint so that relying parties can still verify tokens signed
// before rotation, but they are never used for signing.
//
// Rand is the entropy source for signing operations. If nil (the default),
// [crypto/rand.Reader] is used. Set this for deterministic testing or
// to use a custom entropy source (e.g., an HSM-backed reader).
//
// Do not copy a Signer after first use - it contains an atomic counter.
type Signer struct {
	JWKs // Keys []PublicKey — promoted; marshals as {"keys":[...]}.
	// Note: Keys is exported because json.Marshal needs it for the JWKS
	// endpoint. Callers should not mutate the slice after construction.
	Rand      io.Reader // entropy source for signing; nil means crypto/rand.Reader
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
func NewSigner(keys []PrivateKey, retiredKeys ...PublicKey) (*Signer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("NewSigner: %w", ErrNoSigningKey)
	}
	// Copy so the caller can't mutate after construction.
	ss := make([]PrivateKey, len(keys))
	copy(ss, keys)
	for i := range ss {
		if ss[i].Signer == nil {
			return nil, fmt.Errorf("NewSigner: key[%d] kid %q: %w", i, ss[i].KID, ErrNoSigningKey)
		}

		// Derive algorithm from key type; validate caller's Alg if already set.
		alg, _, _, err := signingParams(ss[i].Signer)
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
			thumb, err := ss[i].Thumbprint()
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
		JWKs: JWKs{Keys: pubs},
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
		return fmt.Errorf("kid %q: %w", pk.KID, ErrNoSigningKey)
	}
	hdr := jws.GetHeader()
	switch {
	case hdr.KID == "":
		hdr.KID = pk.KID
	case hdr.KID != pk.KID:
		return fmt.Errorf("header kid %q vs key kid %q: %w", hdr.KID, pk.KID, ErrKIDConflict)
	}

	alg, hash, ecKeySize, err := signingParams(pk.Signer)
	if err != nil {
		return err
	}

	// Validate and set header algorithm.
	if hdr.Alg != "" && hdr.Alg != alg {
		return fmt.Errorf("key %s vs header %q: %w", alg, hdr.Alg, ErrAlgConflict)
	}
	hdr.Alg = alg

	protected, err := jws.MarshalHeader(hdr)
	if err != nil {
		return err
	}

	input := signingInputBytes(protected, jws.GetPayload())

	rr := s.Rand
	if rr == nil {
		rr = rand.Reader
	}

	// Sign: pre-hash for EC/RSA, or sign raw for Ed25519.
	var sig []byte
	if hash != 0 {
		var digest []byte
		digest, err = digestFor(hash, input)
		if err != nil {
			return err
		}
		sig, err = pk.Signer.Sign(rr, digest, hash)
	} else {
		sig, err = pk.Signer.Sign(rr, input, crypto.Hash(0))
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

// Verifier returns a new [*Verifier] containing the public keys of all
// signing keys plus any retired keys passed to [NewSigner].
func (s *Signer) Verifier() *Verifier {
	// NewSigner already validated keys — duplicates cannot occur here.
	v, _ := NewVerifier(s.Keys)
	return v
}

// validateSigningKey performs a test sign+verify round-trip to catch bad
// keys at construction time rather than on first use.
func validateSigningKey(pk *PrivateKey, pub *PublicKey) error {
	alg, hash, ecKeySize, err := signingParams(pk.Signer)
	if err != nil {
		return err
	}

	testInput := []byte("jwt-key-validation")

	// Sign: pre-hash for EC/RSA, or sign raw for Ed25519.
	var sig []byte
	if hash != 0 {
		var digest []byte
		digest, err = digestFor(hash, testInput)
		if err != nil {
			return err
		}
		sig, err = pk.Signer.Sign(rand.Reader, digest, hash)
	} else {
		sig, err = pk.Signer.Sign(rand.Reader, testInput, crypto.Hash(0))
	}
	if err != nil {
		return fmt.Errorf("test sign %s: %w", alg, err)
	}

	// ECDSA: crypto.Signer returns ASN.1 DER, but JWS (RFC 7515 §A.3)
	// requires IEEE P1363 format (raw r||s concatenation).
	if ecKeySize > 0 {
		sig, err = ecdsaDERToP1363(sig, ecKeySize)
		if err != nil {
			return err
		}
	}

	// Verify against the public key.
	h := Header{Alg: alg, KID: pk.KID}
	if err := verifyOneKey(h, pub.CryptoPublicKey, testInput, sig); err != nil {
		return fmt.Errorf("test verify: %w", err)
	}
	return nil
}
