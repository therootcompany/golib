// Package jwa is the single source of truth for the mapping between
// key types, JWK/JWS identifiers, signing hashes, and coordinate byte
// lengths.
//
// It is internal so that the types and lookup functions do not become
// part of the public API of jwk or jwt.
package jwa

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"fmt"

	"github.com/therootcompany/golib/auth/jwt/jose"
)

// CurveInfo holds the JWK/JWS identifiers and parameters for an EC curve.
type CurveInfo struct {
	Curve   elliptic.Curve // Go curve object
	Crv     string         // JWK "crv" value: "P-256", "P-384", "P-521"
	Alg     string         // JWS algorithm: "ES256", "ES384", "ES512"
	Hash    crypto.Hash    // signing hash: SHA-256, SHA-384, SHA-512
	KeySize int            // coordinate byte length: (BitSize+7)/8
}

// Canonical CurveInfo values — one var per supported curve.
var (
	p256 = CurveInfo{elliptic.P256(), "P-256", "ES256", crypto.SHA256, 32}
	p384 = CurveInfo{elliptic.P384(), "P-384", "ES384", crypto.SHA384, 48}
	p521 = CurveInfo{elliptic.P521(), "P-521", "ES512", crypto.SHA512, 66}
)

// ECInfoForAlg returns the CurveInfo for the given elliptic curve and validates
// that the curve's algorithm matches expectedAlg. This is the verification-side
// check: the key's curve must produce the algorithm the token claims.
func ECInfoForAlg(curve elliptic.Curve, expectedAlg string) (CurveInfo, error) {
	ci, err := ECInfo(curve)
	if err != nil {
		return ci, err
	}
	if ci.Alg != expectedAlg {
		return CurveInfo{}, fmt.Errorf("key curve %s vs token alg %s: %w", ci.Alg, expectedAlg, jose.ErrAlgConflict)
	}
	return ci, nil
}

// ECInfo returns the CurveInfo for the given elliptic curve.
func ECInfo(curve elliptic.Curve) (CurveInfo, error) {
	switch curve {
	case elliptic.P256():
		return p256, nil
	case elliptic.P384():
		return p384, nil
	case elliptic.P521():
		return p521, nil
	default:
		return CurveInfo{}, fmt.Errorf("EC curve %s: %w", curve.Params().Name, jose.ErrUnsupportedCurve)
	}
}

// ECInfoByCrv returns the CurveInfo for a JWK "crv" string.
func ECInfoByCrv(crv string) (CurveInfo, error) {
	switch crv {
	case "P-256":
		return p256, nil
	case "P-384":
		return p384, nil
	case "P-521":
		return p521, nil
	default:
		return CurveInfo{}, fmt.Errorf("EC crv %q: %w", crv, jose.ErrUnsupportedCurve)
	}
}

// SigningParams determines the JWS signing parameters for a crypto.Signer.
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
func SigningParams(s crypto.Signer) (alg string, hash crypto.Hash, ecKeySize int, err error) {
	switch pub := s.Public().(type) {
	case *ecdsa.PublicKey:
		ci, err := ECInfo(pub.Curve)
		if err != nil {
			return "", 0, 0, err
		}
		return ci.Alg, ci.Hash, ci.KeySize, nil
	case *rsa.PublicKey:
		return "RS256", crypto.SHA256, 0, nil
	case ed25519.PublicKey:
		return "EdDSA", 0, 0, nil
	default:
		return "", 0, 0, fmt.Errorf("%T: %w", pub, jose.ErrUnsupportedKeyType)
	}
}
