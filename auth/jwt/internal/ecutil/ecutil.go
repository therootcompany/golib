// Package ecutil is the single source of truth for the mapping between
// elliptic curves, JWK "crv" strings, JWS algorithm strings, signing
// hashes, and coordinate byte lengths.
//
// It is internal so that the type and lookup functions do not become
// part of the public API of jwk or jwt.
package ecutil

import (
	"crypto"
	"crypto/elliptic"
	"fmt"
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

// Info returns the CurveInfo for the given elliptic curve.
func Info(curve elliptic.Curve) (CurveInfo, error) {
	switch curve {
	case elliptic.P256():
		return p256, nil
	case elliptic.P384():
		return p384, nil
	case elliptic.P521():
		return p521, nil
	default:
		return CurveInfo{}, fmt.Errorf("unsupported EC curve: %s", curve.Params().Name)
	}
}

// InfoByCrv returns the CurveInfo for a JWK "crv" string.
func InfoByCrv(crv string) (CurveInfo, error) {
	switch crv {
	case "P-256":
		return p256, nil
	case "P-384":
		return p384, nil
	case "P-521":
		return p521, nil
	default:
		return CurveInfo{}, fmt.Errorf("unsupported EC crv: %q", crv)
	}
}
