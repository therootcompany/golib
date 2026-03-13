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
	"fmt"
	"io"
	"sync/atomic"

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// PrivateKey pairs a [crypto.Signer] with a key ID (KID).
//
// PrivateKey implements [crypto.Signer] so it can be passed directly to
// [JWS.Sign], which auto-sets the KID from [PrivateKey.KID].
//
// If KID is empty, it is auto-computed from the RFC 7638 thumbprint of the
// public key when passed to [NewSigner].
type PrivateKey struct {
	KID    string
	Signer crypto.Signer
}

// Public returns the public key for this PrivateKey.
// Implements [crypto.Signer].
func (pk *PrivateKey) Public() crypto.PublicKey {
	return pk.Signer.Public()
}

// Sign signs digest with the underlying signer.
// Implements [crypto.Signer].
func (pk *PrivateKey) Sign(rand io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return pk.Signer.Sign(rand, digest, opts)
}

// Signer manages one or more private signing keys and issues JWTs by
// round-robining across them.
//
// Do not copy a Signer after first use — it contains an atomic counter.
type Signer struct {
	signers   []PrivateKey
	signerIdx atomic.Uint64
}

// NewSigner creates a Signer from the provided signing keys.
//
// If a PrivateKey's KID is empty, it is auto-computed from the RFC 7638
// thumbprint of the public key. Returns an error if the slice is empty or
// a thumbprint cannot be computed.
func NewSigner(signers []PrivateKey) (*Signer, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("NewSigner: at least one signer is required")
	}
	// Copy so the caller can't mutate after construction.
	ss := make([]PrivateKey, len(signers))
	copy(ss, signers)
	for i, ns := range ss {
		if ns.KID == "" {
			pub, ok := ns.Signer.Public().(jwk.PublicKey)
			if !ok {
				return nil, fmt.Errorf("NewSigner: signer[%d] public key type %T does not implement jwk.PublicKey", i, ns.Signer.Public())
			}
			k := jwk.Key{Key: pub}
			thumb, err := k.Thumbprint()
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
	pk := &s.signers[idx%uint64(len(s.signers))]

	jws, err := NewJWSFromClaims(claims, "")
	if err != nil {
		return "", err
	}
	if _, err := jws.Sign(pk); err != nil {
		return "", err
	}
	return jws.Encode(), nil
}

// Verifier returns a new [*Verifier] containing the public keys of all signing keys.
//
// Use this to construct an Verifier for verifying tokens signed by this Signer.
// For key rotation, combine with old public keys:
//
//	iss := jwt.New(append(signer.PublicKeys(), oldKeys...))
func (s *Signer) Verifier() *Verifier {
	return New(s.PublicKeys())
}

// ToJWKsJSON returns the Signer's public keys as a [jwk.SetJSON] struct.
func (s *Signer) ToJWKsJSON() (jwk.SetJSON, error) {
	return jwk.EncodeSet(s.PublicKeys())
}

// ToJWKs serializes the Signer's public keys as a JWKS JSON document.
func (s *Signer) ToJWKs() ([]byte, error) {
	return jwk.Marshal(s.PublicKeys())
}

// PublicKeys returns the public-key side of each signing key, in the same order
// as the signers were provided to [NewSigner].
func (s *Signer) PublicKeys() []jwk.Key {
	keys := make([]jwk.Key, len(s.signers))
	for i, ns := range s.signers {
		pub, _ := ns.Signer.Public().(jwk.PublicKey)
		keys[i] = jwk.Key{
			Key: pub,
			KID: ns.KID,
		}
	}
	return keys
}
