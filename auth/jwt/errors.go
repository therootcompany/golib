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

// Decode errors — returned by [Decode] when the compact token is malformed.
var (
	ErrMalformedToken   = errors.New("malformed token")
	ErrInvalidHeader    = errors.New("invalid header")
	ErrInvalidSignature = errors.New("invalid signature encoding")
)

// Verification errors — returned by [Verifier.Verify] and [Verifier.VerifyJWT].
var (
	ErrMissingKID       = errors.New("missing kid")
	ErrUnknownKID       = errors.New("unknown kid")
	ErrSignatureInvalid = errors.New("signature invalid")
	ErrKeyTypeMismatch  = errors.New("key type mismatch")
	ErrCurveMismatch    = errors.New("curve mismatch")
	ErrUnsupportedAlg   = errors.New("unsupported algorithm")
)

// Signing errors — returned by [NewSigner], [Signer.SignJWS], and [Signer.Sign].
var (
	ErrNoSigningKey   = errors.New("no signing key")
	ErrAlgConflict    = errors.New("algorithm conflict")
	ErrUnsupportedKey = errors.New("unsupported key type")
)

// Validation errors — returned by [ValidatorCore.Validate],
// [IDTokenValidator.Validate], and [RFCValidator.Validate].
//
// Validate returns all failures at once via [errors.Join], so callers can
// check for specific issues with [errors.Is]:
//
//	err := v.Validate(&claims, time.Now())
//	if errors.Is(err, jwt.ErrAfterExp) { /* token expired */ }
//	if errors.Is(err, jwt.ErrInvalidClaim) { /* any value error, including time-based */ }
//
// The time-based sentinels ([ErrAfterExp], [ErrBeforeNbf], etc.) wrap
// [ErrInvalidClaim], so a single [errors.Is](err, ErrInvalidClaim) check
// catches all value errors.
var (
	ErrValidation = errors.New("validation failed")

	// Generic claim errors.
	ErrMissingClaim = errors.New("missing required claim")
	ErrInvalidClaim = errors.New("invalid claim value")

	// Time-based claim errors — each wraps [ErrInvalidClaim].
	ErrAfterExp        = fmt.Errorf("%w: exp: token expired", ErrInvalidClaim)
	ErrBeforeNbf       = fmt.Errorf("%w: nbf: token not yet valid", ErrInvalidClaim)
	ErrBeforeIat       = fmt.Errorf("%w: iat: issued in the future", ErrInvalidClaim)
	ErrBeforeAuthTime  = fmt.Errorf("%w: auth_time: in the future", ErrInvalidClaim)
	ErrAfterAuthMaxAge = fmt.Errorf("%w: auth_time: exceeds max age", ErrInvalidClaim)
)
