package jwk

import (
	"crypto"
	"crypto/elliptic"
	"fmt"
)

// CurveInfo maps an elliptic curve to its JWK/JWS identifiers and parameters.
// It is the single source of truth for the relationship between Go curve
// objects, JWK "crv" strings, JWS algorithm strings, signing hashes, and
// coordinate byte lengths.
//
// Use [ECCurveInfo] to look up by Go curve object, or [ECCurveInfoByCrv]
// to look up by JWK "crv" string.
type CurveInfo struct {
	Curve   elliptic.Curve // Go curve object
	Crv     string         // JWK "crv" value: "P-256", "P-384", "P-521"
	Alg     string         // JWS algorithm: "ES256", "ES384", "ES512"
	Hash    crypto.Hash    // signing hash: SHA-256, SHA-384, SHA-512
	KeySize int            // coordinate byte length: (BitSize+7)/8
}

// ecCurves is the authoritative table of supported EC curves.
var ecCurves = [...]CurveInfo{
	{elliptic.P256(), "P-256", "ES256", crypto.SHA256, 32},
	{elliptic.P384(), "P-384", "ES384", crypto.SHA384, 48},
	{elliptic.P521(), "P-521", "ES512", crypto.SHA512, 66},
}

// ECCurveInfo returns the CurveInfo for the given elliptic curve.
// Returns an error wrapping [ErrUnsupportedCurve] if the curve is not
// one of P-256, P-384, or P-521.
func ECCurveInfo(curve elliptic.Curve) (CurveInfo, error) {
	for _, ci := range ecCurves {
		if ci.Curve == curve {
			return ci, nil
		}
	}
	return CurveInfo{}, fmt.Errorf("EC curve %s: %w", curve.Params().Name, ErrUnsupportedCurve)
}

// ECCurveInfoByCrv returns the CurveInfo for a JWK "crv" string.
// Returns an error wrapping [ErrUnsupportedCurve] if crv is not
// "P-256", "P-384", or "P-521".
func ECCurveInfoByCrv(crv string) (CurveInfo, error) {
	for _, ci := range ecCurves {
		if ci.Crv == crv {
			return ci, nil
		}
	}
	return CurveInfo{}, fmt.Errorf("EC crv %q: %w", crv, ErrUnsupportedCurve)
}
