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
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"math/big"
	"slices"
)

// Verifier holds the public keys of a JWT issuer and verifies token signatures.
//
// In OIDC terminology, the "issuer" is the identity provider that both signs
// tokens and publishes its public keys. Verifier represents that issuer from
// the relying party's perspective - you hold its public keys and use them to
// verify that tokens were legitimately signed by it.
//
// When a token's kid header matches a key, that key is tried. When the kid is
// empty, every key is tried in order; the first successful verification wins.
//
// Verifier is immutable after construction - safe for concurrent use with no locking.
// Use [NewVerifier] to construct with a fixed key set, or use [Signer.Verifier] or
// [keyfetch.KeyFetcher.Verifier] to obtain one from a signer or remote JWKS endpoint.
type Verifier struct {
	pubKeys []PublicKey
}

// NewVerifier creates a Verifier with an explicit set of public keys.
//
// Multiple keys may share the same KID (e.g. during key rotation).
// When verifying, all keys with a matching KID are tried until one succeeds.
// Keys with identical KID and key material are deduplicated automatically.
//
// The returned Verifier is immutable - keys cannot be added or removed after
// construction. For dynamic key rotation, see keyfetch.KeyFetcher.
func NewVerifier(keys []PublicKey) (*Verifier, error) {
	if len(keys) == 0 {
		return nil, fmt.Errorf("NewVerifier: %w", ErrNoVerificationKey)
	}
	deduped := make([]PublicKey, 0, len(keys))
	type seenEntry struct {
		key   CryptoPublicKey
		index int
	}
	seen := make(map[string][]seenEntry, len(keys))
	for _, k := range keys {
		entries := seen[k.KID]
		dup := false
		for _, e := range entries {
			if e.key.Equal(k.Key) {
				dup = true
				break
			}
		}
		if dup {
			continue // identical key material, skip
		}
		seen[k.KID] = append(entries, seenEntry{key: k.Key, index: len(deduped)})
		deduped = append(deduped, k)
	}
	return &Verifier{
		pubKeys: deduped,
	}, nil
}

// PublicKeys returns a copy of the public keys held by this Verifier.
// Callers may safely modify the returned slice without affecting the Verifier.
//
// To serialize as a JWKS JSON document:
//
//	json.Marshal(WellKnownJWKs{Keys: verifier.PublicKeys()})
func (v *Verifier) PublicKeys() []PublicKey {
	return slices.Clone(v.pubKeys)
}

// Verify checks the signature of an already-decoded [VerifiableJWT].
//
// Key selection by KID:
//   - Token has a KID: all verifier keys with a matching KID are tried
//     (supports key rotation where multiple keys share a KID).
//     Returns [ErrUnknownKID] if no key matches the KID.
//   - Token has no KID: all verifier keys are tried.
//
// In both cases the first successful verification wins.
//
// Returns nil on success, a descriptive error on failure. Claim values
// (iss, aud, exp, etc.) are NOT checked - call [Validator.Validate] on the
// unmarshalled claims after verifying.
//
// Use [Decode] followed by Verify when you need to inspect the header
// (kid, alg) before deciding which verifier to apply:
//
//	jws, err := jwt.Decode(tokenStr)
//	if err != nil { /* malformed */ }
//	// route by kid before verifying
//	if err := chosenVerifier.Verify(jws); err != nil { /* bad sig */ }
//
// Use [Verifier.VerifyJWT] to decode and verify in one step.
func (v *Verifier) Verify(jws VerifiableJWT) error {
	h := jws.GetHeader()
	signingInput := signingInputBytes(jws.GetProtected(), jws.GetPayload())
	sig := jws.GetSignature()

	// Build the candidate key list: all keys with a matching KID, or all
	// keys when the token has no KID. First successful verification wins.
	// Multiple keys may share a KID during key rotation.
	var candidates []PublicKey
	if h.KID != "" {
		for i := range v.pubKeys {
			if v.pubKeys[i].KID == h.KID {
				candidates = append(candidates, v.pubKeys[i])
			}
		}
		if len(candidates) == 0 {
			return fmt.Errorf("kid %q: %w", h.KID, ErrUnknownKID)
		}
	} else {
		candidates = v.pubKeys
	}

	// Try each candidate key. Prefer ErrSignatureInvalid (key type matched
	// but signature bytes didn't verify) over ErrAlgConflict (wrong key type
	// for the token's algorithm) since it's more informative.
	var bestErr error
	for _, pk := range candidates {
		err := verifyOneKey(h, pk.Key, signingInput, sig)
		if err == nil {
			return nil
		}
		if bestErr == nil || errors.Is(err, ErrSignatureInvalid) {
			bestErr = err
		}
	}
	return bestErr
}

// verifyOneKey checks the signature against a single key.
func verifyOneKey(h RFCHeader, key CryptoPublicKey, signingInput, sig []byte) error {
	kid := h.KID
	switch h.Alg {
	case "ES256", "ES384", "ES512":
		k, ok := key.(*ecdsa.PublicKey)
		if !ok {
			return fmt.Errorf("kid %q alg %q: key type %T: %w", kid, h.Alg, key, ErrAlgConflict)
		}
		ci, err := ecInfoForAlg(k.Curve, h.Alg)
		if err != nil {
			return fmt.Errorf("kid %q alg %q: %w", kid, h.Alg, err)
		}
		if len(sig) != 2*ci.KeySize {
			return fmt.Errorf("kid %q alg %q: sig len %d, want %d: %w", kid, h.Alg, len(sig), 2*ci.KeySize, ErrSignatureInvalid)
		}
		digest, err := digestFor(ci.Hash, signingInput)
		if err != nil {
			return fmt.Errorf("kid %q alg %q: %w", kid, h.Alg, err)
		}
		r := new(big.Int).SetBytes(sig[:ci.KeySize])
		s := new(big.Int).SetBytes(sig[ci.KeySize:])
		if !ecdsa.Verify(k, digest, r, s) {
			return fmt.Errorf("kid %q alg %q: %w", kid, h.Alg, ErrSignatureInvalid)
		}
		return nil

	case "RS256":
		k, ok := key.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("kid %q alg %q: key type %T: %w", kid, h.Alg, key, ErrAlgConflict)
		}
		digest, err := digestFor(crypto.SHA256, signingInput)
		if err != nil {
			return fmt.Errorf("kid %q alg %q: %w", kid, h.Alg, err)
		}
		if err := rsa.VerifyPKCS1v15(k, crypto.SHA256, digest, sig); err != nil {
			return fmt.Errorf("kid %q alg %q: %w: %w", kid, h.Alg, ErrSignatureInvalid, err)
		}
		return nil

	case "EdDSA":
		k, ok := key.(ed25519.PublicKey)
		if !ok {
			return fmt.Errorf("kid %q alg %q: key type %T: %w", kid, h.Alg, key, ErrAlgConflict)
		}
		if !ed25519.Verify(k, signingInput, sig) {
			return fmt.Errorf("kid %q alg %q: %w", kid, h.Alg, ErrSignatureInvalid)
		}
		return nil

	default:
		return fmt.Errorf("kid %q alg %q: %w", kid, h.Alg, ErrUnsupportedAlg)
	}
}

// VerifyJWT decodes tokenStr and verifies its signature, returning the parsed
// [*JWT] on success.
//
// Returns (nil, err) on any failure - the caller never receives an
// unauthenticated JWT. Claim values (iss, aud, exp, etc.) are NOT checked;
// call [Validator.Validate] on the unmarshalled claims after VerifyJWT:
//
//	jws, err := v.VerifyJWT(tokenStr)
//	if err != nil { /* bad sig, malformed token, unknown kid */ }
//	var claims AppClaims
//	if err := jws.UnmarshalClaims(&claims); err != nil { /* ... */ }
//	if err := v.Validate(nil, &claims, time.Now()); err != nil { /* ... */ }
//
// For routing by kid/iss before verifying, use [Decode] then [Verifier.Verify].
func (v *Verifier) VerifyJWT(tokenStr string) (*JWT, error) {
	jws, err := Decode(tokenStr)
	if err != nil {
		return nil, err
	}
	if err := v.Verify(jws); err != nil {
		return nil, err
	}
	return jws, nil
}
