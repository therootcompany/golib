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
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sync/atomic"

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
	jwk.JWKs  // Keys []jwk.PublicKey - promoted; marshals as {"keys":[...]}
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
		return nil, fmt.Errorf("NewSigner: %w", ErrNoSigningKey)
	}
	// Copy so the caller can't mutate after construction.
	ss := make([]jwk.PrivateKey, len(keys))
	copy(ss, keys)
	for i := range ss {
		if ss[i].Signer == nil {
			return nil, fmt.Errorf("NewSigner: key[%d] kid %q: %w", i, ss[i].KID, ErrNoSigningKey)
		}

		// Derive algorithm from key type; validate caller's Alg if already set.
		alg, err := algForSigner(ss[i].Signer)
		if err != nil {
			return nil, fmt.Errorf("NewSigner: key[%d]: %w", i, err)
		}
		if ss[i].Alg != "" && ss[i].Alg != alg {
			return nil, fmt.Errorf("NewSigner: key[%d] alg %q expected %s: %w", i, ss[i].Alg, alg, ErrAlgConflict)
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
		return "", fmt.Errorf("%T: %w", pub, ErrUnsupportedKey)
	}
}

// SignJWS signs jws in-place using the next signing key in round-robin order
// and returns the signature bytes.
//
// The KID and alg header fields are set automatically from the selected key.
// Use this when you need the full signed JWS for further processing
// (e.g., inspecting headers before encoding). For the common one-step cases,
// prefer [Signer.Sign] or [Signer.SignToString].
func (s *Signer) SignJWS(jws SignableJWS) error {
	idx := s.signerIdx.Add(1) - 1
	pk := &s.keys[idx%uint64(len(s.keys))]
	return signWith(jws, pk)
}

// signWith is the shared implementation used by [Signer.SignJWS]. It selects
// the algorithm from the key type, validates any
// pre-set alg/kid in the JWS header, then calls [SignableJWS.MarshalHeader]
// and [SignableJWS.SetSignature] so custom JWS types need no crypto knowledge.
//
// pk must have a non-nil Signer. KID is taken from pk.KID - set automatically
// if the header's KID is empty; an error is returned on mismatch.
func signWith(jws SignableJWS, pk *jwk.PrivateKey) error {
	if pk.Signer == nil {
		return fmt.Errorf("signWith: kid %q: %w", pk.KID, ErrNoSigningKey)
	}
	hdr := jws.GetHeader()
	switch {
	case hdr.KID == "":
		hdr.KID = pk.KID
	case hdr.KID != pk.KID:
		return fmt.Errorf("signWith: header kid %q vs key kid %q: %w", hdr.KID, pk.KID, ErrKIDConflict)
	}

	switch pub := pk.Signer.Public().(type) {
	case *ecdsa.PublicKey:
		alg, h, err := algForECKey(pub)
		if err != nil {
			return err
		}
		if hdr.Alg != "" && hdr.Alg != alg {
			return fmt.Errorf("signWith: key %s vs header %q: %w", alg, hdr.Alg, ErrAlgConflict)
		}
		hdr.Alg = alg
		protected, err := jws.MarshalHeader(hdr)
		if err != nil {
			return err
		}
		digest, err := digestFor(h, signingInputBytes(protected, jws.GetPayload()))
		if err != nil {
			return err
		}
		// crypto.Signer returns ASN.1 DER for ECDSA; convert to raw r||s for JWS.
		derSig, err := pk.Signer.Sign(rand.Reader, digest, h)
		if err != nil {
			return fmt.Errorf("signWith %s: %w", alg, err)
		}
		sig, err := ecdsaDERToRaw(derSig, pub.Curve)
		if err != nil {
			return err
		}
		jws.SetSignature(sig)
		return nil

	case *rsa.PublicKey:
		if hdr.Alg != "" && hdr.Alg != "RS256" {
			return fmt.Errorf("signWith: RSA vs header %q: %w", hdr.Alg, ErrAlgConflict)
		}
		hdr.Alg = "RS256"
		protected, err := jws.MarshalHeader(hdr)
		if err != nil {
			return err
		}
		digest, err := digestFor(crypto.SHA256, signingInputBytes(protected, jws.GetPayload()))
		if err != nil {
			return err
		}
		// crypto.Signer returns raw PKCS#1 v1.5 bytes for RSA; use directly.
		sig, err := pk.Signer.Sign(rand.Reader, digest, crypto.SHA256)
		if err != nil {
			return fmt.Errorf("signWith RS256: %w", err)
		}
		jws.SetSignature(sig)
		return nil

	case ed25519.PublicKey:
		if hdr.Alg != "" && hdr.Alg != "EdDSA" {
			return fmt.Errorf("signWith: EdDSA vs header %q: %w", hdr.Alg, ErrAlgConflict)
		}
		hdr.Alg = "EdDSA"
		protected, err := jws.MarshalHeader(hdr)
		if err != nil {
			return err
		}
		// Ed25519 signs the raw message with no pre-hashing; pass crypto.Hash(0).
		sig, err := pk.Signer.Sign(rand.Reader, signingInputBytes(protected, jws.GetPayload()), crypto.Hash(0))
		if err != nil {
			return fmt.Errorf("signWith EdDSA: %w", err)
		}
		jws.SetSignature(sig)
		return nil

	default:
		return fmt.Errorf(
			"signWith: %T: %w",
			pk.Signer.Public(), ErrUnsupportedKey,
		)
	}
}

// Sign creates a JWS from claims, signs it with the next signing key,
// and returns the signed JWS.
//
// Use this when you need access to the signed JWS object (e.g., to inspect
// headers or read the raw signature). For the common case of producing a
// compact token string, use [Signer.SignToString].
func (s *Signer) Sign(claims Claims) (*JWS, error) {
	jws, err := NewJWS(claims)
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
	return NewVerifier(s.Keys)
}
