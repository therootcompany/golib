// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import "github.com/therootcompany/golib/auth/jwt/jose"

// All sentinel errors are defined in [jose] and re-exported here so
// callers can use either jwt.ErrFoo or jose.ErrFoo — they are the same
// pointer, so [errors.Is] works regardless of which import path is used.

// Decode errors — returned by [Decode] and [UnmarshalClaims] when the
// compact token or its components are malformed.
var (
	ErrMalformedToken   = jose.ErrMalformedToken
	ErrInvalidHeader    = jose.ErrInvalidHeader
	ErrInvalidPayload   = jose.ErrInvalidPayload
	ErrInvalidSignature = jose.ErrInvalidSignature
)

// Verification errors — returned by [Verifier.Verify] and [Verifier.VerifyJWT].
var (
	ErrMissingKID       = jose.ErrMissingKID
	ErrUnknownKID       = jose.ErrUnknownKID
	ErrSignatureInvalid = jose.ErrSignatureInvalid
	ErrKeyTypeMismatch  = jose.ErrKeyTypeMismatch
	ErrCurveMismatch    = jose.ErrCurveMismatch
	ErrUnsupportedAlg   = jose.ErrUnsupportedAlg
)

// Signing errors — returned by [NewSigner], [Signer.SignJWS], and [Signer.Sign].
var (
	ErrNoSigningKey = jose.ErrNoSigningKey
	ErrAlgConflict  = jose.ErrAlgConflict
	ErrKIDConflict  = jose.ErrKIDConflict
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
	ErrValidation = jose.ErrValidation

	// Generic claim errors.
	ErrMissingClaim = jose.ErrMissingClaim
	ErrInvalidClaim = jose.ErrInvalidClaim

	// Time-based claim errors — each wraps [ErrInvalidClaim].
	ErrAfterExp        = jose.ErrAfterExp
	ErrBeforeNbf       = jose.ErrBeforeNbf
	ErrBeforeIat       = jose.ErrBeforeIat
	ErrBeforeAuthTime  = jose.ErrBeforeAuthTime
	ErrAfterAuthMaxAge = jose.ErrAfterAuthMaxAge
)
