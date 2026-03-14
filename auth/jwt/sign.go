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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"fmt"
	"sync/atomic"

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// Signer manages one or more private signing keys and issues JWTs by
// round-robining across them. It is the issuing side of a JWT issuer —
// the party that signs tokens with a private key and publishes the
// corresponding public keys.
//
// Signer embeds [jwk.JWKs], so the JWKS endpoint response is just:
//
//	json.Marshal(&signer)
//
// Do not copy a Signer after first use — it contains an atomic counter.
type Signer struct {
	jwk.JWKs              // Keys []jwk.PublicKey — promoted; marshals as {"keys":[...]}
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
func NewSigner(keys []jwk.PrivateKey) (*Signer, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("NewSigner: at least one key is required")
	}
	// Copy so the caller can't mutate after construction.
	ss := make([]jwk.PrivateKey, len(keys))
	copy(ss, keys)
	for i := range ss {
		if ss[i].Signer == nil {
			return nil, fmt.Errorf("NewSigner: key[%d] (kid=%q) has no Signer", i, ss[i].KID)
		}

		// Derive algorithm from key type; validate caller's Alg if already set.
		alg, err := algForSigner(ss[i].Signer)
		if err != nil {
			return nil, fmt.Errorf("NewSigner: key[%d]: %w", i, err)
		}
		if ss[i].Alg != "" && ss[i].Alg != alg {
			return nil, fmt.Errorf("NewSigner: key[%d] Alg %q conflicts with key type (expected %s)", i, ss[i].Alg, alg)
		}
		ss[i].Alg = alg

		// Default Use to "sig" for signing keys.
		if ss[i].Use == "" {
			ss[i].Use = "sig"
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

	pubs := make([]jwk.PublicKey, len(ss))
	for i := range ss {
		pubs[i] = *ss[i].PublicKey()
	}
	return &Signer{
		JWKs: jwk.JWKs{Keys: pubs},
		keys: ss,
	}, nil
}

// algForSigner returns the JWS algorithm string for the given crypto.Signer's key type.
func algForSigner(s crypto.Signer) (string, error) {
	switch pub := s.Public().(type) {
	case *ecdsa.PublicKey:
		alg, _, err := algForECKey(pub)
		return alg, err
	case *rsa.PublicKey:
		return "RS256", nil
	case ed25519.PublicKey:
		return "EdDSA", nil
	default:
		return "", fmt.Errorf("unsupported key type %T (supported: *ecdsa.PublicKey, *rsa.PublicKey, ed25519.PublicKey)", pub)
	}
}

// SignJWS signs jws in-place using the next signing key in round-robin order
// and returns the signature bytes.
//
// The KID and alg header fields are set automatically from the selected key.
// Use this when you need the full signed JWS for further processing
// (e.g., inspecting headers before encoding). For the common one-step cases,
// prefer [Signer.Sign] or [Signer.SignToString].
func (s *Signer) SignJWS(jws SignableJWS) ([]byte, error) {
	idx := s.signerIdx.Add(1) - 1
	pk := &s.keys[idx%uint64(len(s.keys))]
	return signWith(jws, pk)
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
// Use this to construct a Verifier for verifying tokens signed by this Signer.
// For key rotation, combine with old public keys:
//
//	iss := jwt.New(append(signer.Keys, oldKeys...))
func (s *Signer) Verifier() *Verifier {
	return New(s.Keys)
}
