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
	"encoding/json"
	"fmt"
	"sync/atomic"

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// PrivateKey pairs a [crypto.Signer] with a key ID (KID).
//
// Pass *PrivateKey to [StandardJWS.Sign], which auto-applies the KID to the
// JOSE header.
//
// If KID is empty, it is auto-computed from the RFC 7638 thumbprint of the
// public key when passed to [NewSigner].
//
// https://www.rfc-editor.org/rfc/rfc7638.html
type PrivateKey struct {
	KID    string
	Signer crypto.Signer
}

// Signer manages one or more private signing keys and issues JWTs by
// round-robining across them. It is the issuing side of a JWT issuer —
// the party that signs tokens with a private key and publishes the
// corresponding public keys via [Signer.Verifier] or [Signer.ToJWKs].
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
//
// https://www.rfc-editor.org/rfc/rfc7638.html
func NewSigner(signers []PrivateKey) (*Signer, error) {
	if len(signers) == 0 {
		return nil, fmt.Errorf("NewSigner: at least one signer is required")
	}
	// Copy so the caller can't mutate after construction.
	ss := make([]PrivateKey, len(signers))
	copy(ss, signers)
	for i, ns := range ss {
		if ns.KID == "" {
			pub, ok := ns.Signer.Public().(jwk.CryptoPublicKey)
			if !ok {
				return nil, fmt.Errorf("NewSigner: signer[%d] public key type %T does not implement jwk.CryptoPublicKey", i, ns.Signer.Public())
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

// SignJWS signs jws in-place using the next signing key in round-robin order
// and returns the signature bytes.
//
// The KID and alg header fields are set automatically from the selected key.
// Use this when you need the full signed *StandardJWS for further processing
// (e.g., inspecting headers before encoding). For the common one-step cases,
// prefer [Signer.Sign] or [Signer.SignToString].
func (s *Signer) SignJWS(jws *StandardJWS) ([]byte, error) {
	idx := s.signerIdx.Add(1) - 1
	pk := &s.signers[idx%uint64(len(s.signers))]
	return jws.Sign(pk)
}

// Sign creates a StandardJWS from claims, signs it with the next signing key,
// and returns the signed JWS.
//
// Use this when you need access to the signed JWS object (e.g., to inspect
// headers or read the raw signature). For the common case of producing a
// compact token string, use [Signer.SignToString].
func (s *Signer) Sign(claims Claims) (*StandardJWS, error) {
	jws, err := NewJWS(claims)
	if err != nil {
		return nil, err
	}
	if _, err := s.SignJWS(jws); err != nil {
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

// ToJWKs serializes the Signer's public keys as a JWKS JSON document.
func (s *Signer) ToJWKs() ([]byte, error) {
	return json.Marshal(jwk.JWKs{Keys: s.PublicKeys()})
}

// PublicKeys returns the public-key side of each signing key, in the same order
// as the signers were provided to [NewSigner].
func (s *Signer) PublicKeys() []jwk.Key {
	keys := make([]jwk.Key, len(s.signers))
	for i, ns := range s.signers {
		pub, _ := ns.Signer.Public().(jwk.CryptoPublicKey)
		keys[i] = jwk.Key{
			Key: pub,
			KID: ns.KID,
		}
	}
	return keys
}
