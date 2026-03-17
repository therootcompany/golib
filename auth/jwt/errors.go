// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"errors"
	"fmt"
)

// Sentinel errors for decode, signature, key, signing, and verification.
//
// These are the operational errors returned by [Decode], [Verifier.Verify],
// [Signer.SignJWT], [NewSigner], and related functions. For claim validation
// errors, see the Err* variables below.
var (
	// Decode errors - returned by [Decode] and [RawJWT.UnmarshalClaims]
	// when the compact token or its components are malformed.
	ErrMalformedToken = errors.New("malformed token")
	ErrInvalidHeader  = errors.New("invalid header")
	ErrInvalidPayload = errors.New("invalid payload")

	// Signature and algorithm errors - returned during signing and
	// verification when the signature, algorithm, or key type is wrong.
	ErrSignatureInvalid   = errors.New("signature invalid")
	ErrUnsupportedAlg     = errors.New("unsupported algorithm")
	ErrAlgConflict        = errors.New("algorithm conflict")
	ErrUnsupportedKeyType = errors.New("unsupported key type")
	ErrUnsupportedCurve   = errors.New("unsupported curve")

	// Key errors - returned when key material is invalid or insufficient.
	ErrInvalidKey        = errors.New("invalid key")
	ErrKeyTooSmall       = fmt.Errorf("%w: key too small", ErrInvalidKey)
	ErrMissingKeyData    = fmt.Errorf("%w: missing key data", ErrInvalidKey)
	ErrUnsupportedFormat = errors.New("unsupported format")

	// Verification errors - returned by [Verifier.Verify] and
	// [Signer.SignJWT] when no key matches the token's kid.
	ErrUnknownKID        = errors.New("unknown kid")
	ErrNoVerificationKey = errors.New("no verification keys")

	// Signing errors - returned by [NewSigner] and [Signer.SignJWT].
	ErrNoSigningKey = errors.New("no signing key")

	// Sanity errors - internal invariant violations that should never
	// happen given the library's own validation.
	ErrSanityFail = errors.New("something impossible happened")
)

// Sentinel errors for claim validation.
//
// [Validator.Validate] returns all failures at once via [errors.Join].
// Check for specific issues with [errors.Is]:
//
//	err := v.Validate(nil, &claims, time.Now())
//	if errors.Is(err, jwt.ErrAfterExp)     { /* token expired */ }
//	if errors.Is(err, jwt.ErrInvalidClaim) { /* any value error */ }
//
// The time-based sentinels (ErrAfterExp, ErrBeforeNBf, etc.) wrap
// ErrInvalidClaim, so a single errors.Is(err, ErrInvalidClaim) check
// catches all value errors.
//
// Use [ValidationErrors] to extract structured [*ValidationError] values
// for API responses, or [GetOAuth2Error] for OAuth 2.0 error responses.
var (
	// Claim-level errors.
	ErrMissingClaim      = errors.New("missing required claim")
	ErrInvalidClaim      = errors.New("invalid claim value")
	ErrInvalidTyp        = errors.New("invalid typ header")
	ErrInsufficientScope = errors.New("insufficient scope")

	// Time-based claim errors - each wraps ErrInvalidClaim.
	ErrAfterExp        = fmt.Errorf("%w: exp: token expired", ErrInvalidClaim)
	ErrBeforeNBf       = fmt.Errorf("%w: nbf: token not yet valid", ErrInvalidClaim)
	ErrBeforeIAt       = fmt.Errorf("%w: iat: issued in the future", ErrInvalidClaim)
	ErrBeforeAuthTime  = fmt.Errorf("%w: auth_time: in the future", ErrInvalidClaim)
	ErrAfterAuthMaxAge = fmt.Errorf("%w: auth_time: exceeds max age", ErrInvalidClaim)

	// Server-side misconfiguration - the validator itself is invalid.
	// Callers should treat this as a 500 (server error), not 401 (unauthorized).
	ErrMisconfigured = errors.New("validator misconfigured")
)
