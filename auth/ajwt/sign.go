// Copyright 2025 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package ajwt

import (
	"crypto"
	"fmt"
	"sync/atomic"
)

// NamedSigner pairs a [crypto.Signer] with a key ID (KID).
//
// If KID is empty, it is auto-computed from the RFC 7638 thumbprint of the
// public key when passed to [NewSigner].
type NamedSigner struct {
	KID    string
	Signer crypto.Signer
}

// Signer manages one or more private signing keys and issues JWTs by
// round-robining across them.
//
// Do not copy a Signer after first use — it contains an atomic counter.
type Signer struct {
	signers   []NamedSigner
	signerIdx atomic.Uint64
}

// NewSigner creates a Signer from the provided signing keys.
//
// If a NamedSigner's KID is empty, it is auto-computed from the RFC 7638
// thumbprint of the public key. Returns an error if the slice is empty or
// a thumbprint cannot be computed.
func NewSigner(signers []NamedSigner) (*Signer, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("NewSigner: at least one signer is required")
	}
	// Copy so the caller can't mutate after construction.
	ss := make([]NamedSigner, len(signers))
	copy(ss, signers)
	for i, ns := range ss {
		if ns.KID == "" {
			jwk := PublicJWK{Key: ns.Signer.Public()}
			thumb, err := jwk.Thumbprint()
			if err != nil {
				return nil, fmt.Errorf("NewSigner: compute thumbprint for signer[%d]: %w", i, err)
			}
			ss[i].KID = thumb
		}
	}
	return &Signer{signers: ss}, nil
}

// Sign creates and signs a compact JWT from claims, using the next signing key
// in round-robin order. The caller is responsible for setting the "iss" field
// in claims if issuer identification is needed.
func (s *Signer) Sign(claims any) (string, error) {
	idx := s.signerIdx.Add(1) - 1
	ns := s.signers[idx%uint64(len(s.signers))]

	jws, err := NewJWSFromClaims(claims, ns.KID)
	if err != nil {
		return "", err
	}
	if _, err := jws.Sign(ns.Signer); err != nil {
		return "", err
	}
	return jws.Encode(), nil
}

// Issuer returns a new [*Issuer] containing the public keys of all signing keys.
//
// Use this to construct an Issuer for verifying tokens signed by this Signer.
// For key rotation, combine with old public keys:
//
//	iss := ajwt.New(append(signer.PublicKeys(), oldKeys...))
func (s *Signer) Issuer() *Issuer {
	return New(s.PublicKeys())
}

// ToJWKsJSON returns the Signer's public keys as a [JWKsJSON] struct.
func (s *Signer) ToJWKsJSON() (JWKsJSON, error) {
	return ToJWKsJSON(s.PublicKeys())
}

// ToJWKs serializes the Signer's public keys as a JWKS JSON document.
func (s *Signer) ToJWKs() ([]byte, error) {
	return ToJWKs(s.PublicKeys())
}

// PublicKeys returns the public-key side of each signing key, in the same order
// as the signers were provided to [NewSigner].
func (s *Signer) PublicKeys() []PublicJWK {
	keys := make([]PublicJWK, len(s.signers))
	for i, ns := range s.signers {
		keys[i] = PublicJWK{
			Key: ns.Signer.Public(),
			KID: ns.KID,
		}
	}
	return keys
}
