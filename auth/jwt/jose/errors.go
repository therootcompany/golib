// Package jose holds sentinel errors shared across the jwt, jwk, and
// internal jwa packages. It is the leaf of the dependency graph (no
// imports of its siblings), so every package in the module can import
// it without creating cycles.
//
// All sentinel errors for the module live here so that callers can
// match on a single import path regardless of which layer produced the
// error. The jwt and jwk packages re-export every sentinel under their
// own package name for convenience:
//
//	errors.Is(err, jwt.ErrAfterExp)   // works
//	errors.Is(err, jose.ErrAfterExp)  // also works — same pointer
package jose

import (
	"errors"
	"fmt"
)

// --- Decode errors ---
// Returned by jwt.Decode and jwt.UnmarshalClaims when the compact token
// or its components are malformed.
var (
	ErrMalformedToken   = errors.New("malformed token")
	ErrInvalidHeader    = errors.New("invalid header")
	ErrInvalidPayload   = errors.New("invalid payload")
	ErrInvalidSignature = errors.New("invalid signature encoding")
)

// --- Verification errors ---
// Returned by jwt.Verifier.Verify and jwt.Verifier.VerifyJWT.
var (
	ErrMissingKID       = errors.New("missing kid")
	ErrUnknownKID       = errors.New("unknown kid")
	ErrSignatureInvalid = errors.New("signature invalid")
	ErrKeyTypeMismatch  = errors.New("key type mismatch")
	ErrCurveMismatch    = errors.New("curve mismatch")
	ErrUnsupportedAlg   = errors.New("unsupported algorithm")
)

// --- Signing errors ---
// Returned by jwt.NewSigner, jwt.Signer.SignJWS, and jwt.Signer.Sign.
var (
	ErrNoSigningKey = errors.New("no signing key")
	ErrAlgConflict  = errors.New("algorithm conflict")
	ErrKIDConflict  = errors.New("kid conflict")
)

// --- Key type / curve errors ---
// Shared by jwt, jwk, and internal/jwa.
var (
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	ErrUnsupportedCurve   = errors.New("unsupported curve")
)

// --- Key parsing errors ---
// Returned by jwk.PublicKey.UnmarshalJSON, jwk.PrivateKey.UnmarshalJSON,
// and jwk.ReadFile.
var (
	ErrInvalidKey    = errors.New("invalid key")
	ErrKeyTooSmall   = fmt.Errorf("%w: key too small", ErrInvalidKey)
	ErrMissingKeyData = fmt.Errorf("%w: missing key data", ErrInvalidKey)
)

// --- Fetch errors ---
// Returned by jwk.FetchURL, jwk.FetchOIDC, and jwk.FetchOAuth2.
var (
	ErrFetchFailed      = errors.New("fetch failed")
	ErrUnexpectedStatus = fmt.Errorf("%w: unexpected status", ErrFetchFailed)
)

// --- Validation errors ---
// Returned by jwt.ValidatorCore.Validate, jwt.IDTokenValidator.Validate,
// and jwt.RFCValidator.Validate.
//
// Validate returns all failures at once via errors.Join, so callers can
// check for specific issues with errors.Is:
//
//	err := v.Validate(&claims, time.Now())
//	if errors.Is(err, jose.ErrAfterExp) { /* token expired */ }
//	if errors.Is(err, jose.ErrInvalidClaim) { /* any value error */ }
//
// The time-based sentinels (ErrAfterExp, ErrBeforeNbf, etc.) wrap
// ErrInvalidClaim, so a single errors.Is(err, ErrInvalidClaim) check
// catches all value errors.
var (
	ErrValidation = errors.New("validation failed")

	// Generic claim errors.
	ErrMissingClaim = errors.New("missing required claim")
	ErrInvalidClaim = errors.New("invalid claim value")

	// Time-based claim errors — each wraps ErrInvalidClaim.
	ErrAfterExp        = fmt.Errorf("%w: exp: token expired", ErrInvalidClaim)
	ErrBeforeNbf       = fmt.Errorf("%w: nbf: token not yet valid", ErrInvalidClaim)
	ErrBeforeIat       = fmt.Errorf("%w: iat: issued in the future", ErrInvalidClaim)
	ErrBeforeAuthTime  = fmt.Errorf("%w: auth_time: in the future", ErrInvalidClaim)
	ErrAfterAuthMaxAge = fmt.Errorf("%w: auth_time: exceeds max age", ErrInvalidClaim)
)
