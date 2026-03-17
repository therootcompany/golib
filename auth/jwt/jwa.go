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
	"crypto/elliptic"
	"crypto/rsa"
	_ "crypto/sha256" // register SHA-256 with crypto.Hash
	_ "crypto/sha512" // register SHA-384 and SHA-512 with crypto.Hash
	"encoding/asn1"
	"fmt"
	"math/big"
)

// curveInfo holds the JWK/JWS identifiers and parameters for an EC curve.
type curveInfo struct {
	Curve   elliptic.Curve // Go curve object
	Crv     string         // JWK "crv" value: "P-256", "P-384", "P-521"
	Alg     string         // JWS algorithm: "ES256", "ES384", "ES512"
	Hash    crypto.Hash    // signing hash: SHA-256, SHA-384, SHA-512
	KeySize int            // coordinate byte length: (BitSize+7)/8
}

// Canonical curveInfo values - one var per supported curve.
var (
	p256 = curveInfo{elliptic.P256(), "P-256", "ES256", crypto.SHA256, 32}
	p384 = curveInfo{elliptic.P384(), "P-384", "ES384", crypto.SHA384, 48}
	p521 = curveInfo{elliptic.P521(), "P-521", "ES512", crypto.SHA512, 66}
)

// ecInfoForAlg returns the curveInfo for the given elliptic curve and validates
// that the curve's algorithm matches expectedAlg. This is the verification-side
// check: the key's curve must produce the algorithm the token claims.
func ecInfoForAlg(curve elliptic.Curve, expectedAlg string) (curveInfo, error) {
	ci, err := ecInfo(curve)
	if err != nil {
		return ci, err
	}
	if ci.Alg != expectedAlg {
		return curveInfo{}, fmt.Errorf("key curve %s vs token alg %s: %w", ci.Alg, expectedAlg, ErrAlgConflict)
	}
	return ci, nil
}

// ecInfo returns the curveInfo for the given elliptic curve.
func ecInfo(curve elliptic.Curve) (curveInfo, error) {
	switch curve {
	case elliptic.P256():
		return p256, nil
	case elliptic.P384():
		return p384, nil
	case elliptic.P521():
		return p521, nil
	default:
		return curveInfo{}, fmt.Errorf("EC curve %s: %w", curve.Params().Name, ErrUnsupportedCurve)
	}
}

// ecInfoByCrv returns the curveInfo for a JWK "crv" string.
func ecInfoByCrv(crv string) (curveInfo, error) {
	switch crv {
	case "P-256":
		return p256, nil
	case "P-384":
		return p384, nil
	case "P-521":
		return p521, nil
	default:
		return curveInfo{}, fmt.Errorf("EC crv %q: %w", crv, ErrUnsupportedCurve)
	}
}

// signingParams determines the JWS signing parameters for a crypto.Signer.
//
// It type-switches on s.Public() (not on s directly) so that non-standard
// crypto.Signer implementations (KMS, HSM) work as long as they expose a
// standard public key type.
//
// Returns:
//   - alg: JWS algorithm string (ES256, ES384, ES512, RS256, EdDSA)
//   - hash: crypto.Hash for pre-hashing; 0 for Ed25519 (sign raw message)
//   - ecKeySize: ECDSA coordinate byte length; >0 signals that the
//     signature needs ASN.1 DER to IEEE P1363 conversion
func signingParams(s crypto.Signer) (alg string, hash crypto.Hash, ecKeySize int, err error) {
	switch pub := s.Public().(type) {
	case *ecdsa.PublicKey:
		ci, err := ecInfo(pub.Curve)
		if err != nil {
			return "", 0, 0, err
		}
		return ci.Alg, ci.Hash, ci.KeySize, nil
	case *rsa.PublicKey:
		return "RS256", crypto.SHA256, 0, nil
	case ed25519.PublicKey:
		return "EdDSA", 0, 0, nil
	default:
		return "", 0, 0, fmt.Errorf("%T: %w", pub, ErrUnsupportedKeyType)
	}
}

// signingInputBytes builds the protected.payload byte slice used as the signing input.
func signingInputBytes(protected, payload []byte) []byte {
	out := make([]byte, 0, len(protected)+1+len(payload))
	out = append(out, protected...)
	out = append(out, '.')
	out = append(out, payload...)
	return out
}

// digestFor hashes data with the given crypto.Hash.
func digestFor(h crypto.Hash, data []byte) ([]byte, error) {
	if !h.Available() {
		return nil, fmt.Errorf("hash %v: %w", h, ErrUnsupportedAlg)
	}
	hh := h.New()
	hh.Write(data)
	return hh.Sum(nil), nil
}

// ecdsaDERToP1363 converts an ASN.1 DER-encoded ECDSA signature to
// the fixed-width IEEE P1363 format used by JWS.
func ecdsaDERToP1363(der []byte, keySize int) ([]byte, error) {
	var sig struct{ R, S *big.Int }
	rest, err := asn1.Unmarshal(der, &sig)
	if err != nil {
		return nil, err
	}
	if len(rest) > 0 {
		return nil, fmt.Errorf("%d trailing ASN.1 bytes: %w", len(rest), ErrSignatureInvalid)
	}
	// Validate that R and S fit in keySize bytes before FillBytes.
	rLen := (sig.R.BitLen() + 7) / 8
	sLen := (sig.S.BitLen() + 7) / 8
	if rLen > keySize || sLen > keySize {
		return nil, fmt.Errorf("R (%d bytes) or S (%d bytes) exceeds key size %d: %w",
			rLen, sLen, keySize, ErrSignatureInvalid)
	}
	out := make([]byte, 2*keySize)
	sig.R.FillBytes(out[:keySize])
	sig.S.FillBytes(out[keySize:])
	return out, nil
}
