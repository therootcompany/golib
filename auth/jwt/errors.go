package jwt

import (
	"errors"
	"fmt"
)

// --- Decode errors ---
// Returned by [Decode] and [UnmarshalClaims] when the compact token
// or its components are malformed.
var (
	ErrMalformedToken = errors.New("malformed token")
	ErrInvalidHeader  = errors.New("invalid header")
	ErrInvalidPayload = errors.New("invalid payload")
)

// --- Signature errors ---
// Returned during signing, verification, and decoding when the
// signature is malformed, cryptographically invalid, or cannot be
// produced.
var (
	ErrSignatureInvalid = errors.New("signature invalid")
)

// --- Verification errors ---
// Returned by [Verifier.Verify] and [Verifier.VerifyJWT].
var (
	ErrMissingKID   = errors.New("missing kid")
	ErrUnknownKID   = errors.New("unknown kid")
	ErrUnsupportedAlg = errors.New("unsupported algorithm")
)

// --- Key / algorithm errors ---
// Returned when the key type, curve, or algorithm is unsupported or
// conflicts between the key and the operation being performed.
var (
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	ErrUnsupportedCurve   = errors.New("unsupported curve")
	ErrAlgConflict        = errors.New("algorithm conflict")
	ErrKIDConflict        = errors.New("kid conflict")
)

// --- Signing errors ---
// Returned by [NewSigner], [Signer.SignJWS], and [Signer.Sign].
var (
	ErrNoSigningKey = errors.New("no signing key")
)

// --- Key parsing errors ---
// Returned by [PublicKey.UnmarshalJSON], [PrivateKey.UnmarshalJSON],
// Parse*, Load*, and the keyfile.Parse*/keyfile.Load* functions.
var (
	ErrInvalidKey        = errors.New("invalid key")
	ErrKeyTooSmall       = fmt.Errorf("%w: key too small", ErrInvalidKey)
	ErrMissingKeyData    = fmt.Errorf("%w: missing key data", ErrInvalidKey)
	ErrUnsupportedFormat = errors.New("unsupported format")
)

// --- Sanity errors ---
// Returned when an internal invariant is violated — conditions that should
// be impossible given the library's own validation, but are checked
// defensively against unexpected key types or runtime behavior.
var (
	ErrSanityFail = errors.New("something impossible happened")
)

// --- Fetch errors ---
// Returned by [Fetch], [FetchURL], [FetchOIDC], and [FetchOAuth2].
var (
	ErrFetchFailed      = errors.New("fetch failed")
	ErrUnexpectedStatus = fmt.Errorf("%w: unexpected status", ErrFetchFailed)
)

// --- Validation errors ---
// Returned by [IDTokenValidator.Validate] and [AccessTokenValidator.Validate].
//
// Validate returns all failures at once via errors.Join, so callers can
// check for specific issues with errors.Is:
//
//	err := v.Validate(&claims, time.Now())
//	if errors.Is(err, jwt.ErrAfterExp) { /* token expired */ }
//	if errors.Is(err, jwt.ErrInvalidClaim) { /* any value error */ }
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

	// Server-side misconfiguration — the validator itself is invalid.
	// Callers should treat this as a 500 (server error), not 401 (unauthorized).
	ErrMisconfigured = errors.New("validator misconfigured")
)
