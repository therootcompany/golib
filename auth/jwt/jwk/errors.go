// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwk

import "github.com/therootcompany/golib/auth/jwt/jose"

// All sentinel errors are defined in [jose] and re-exported here so
// callers can use either jwk.ErrFoo or jose.ErrFoo — they are the same
// pointer, so [errors.Is] works regardless of which import path is used.

// Key parsing errors — returned by [PublicKey.UnmarshalJSON],
// [PrivateKey.UnmarshalJSON], and [ReadFile].
var (
	// ErrInvalidKey is the broad category for any key that cannot be
	// decoded or fails validation. More specific sentinels below wrap it.
	ErrInvalidKey = jose.ErrInvalidKey

	// ErrUnsupportedKeyType indicates an unrecognized JWK "kty" value.
	ErrUnsupportedKeyType = jose.ErrUnsupportedKeyType

	// ErrUnsupportedCurve indicates an unrecognized JWK "crv" value.
	ErrUnsupportedCurve = jose.ErrUnsupportedCurve

	// ErrKeyTooSmall indicates a key that does not meet the minimum size.
	ErrKeyTooSmall = jose.ErrKeyTooSmall

	// ErrMissingKeyData indicates required key material is absent.
	ErrMissingKeyData = jose.ErrMissingKeyData
)

// Fetch errors — returned by [FetchURL], [FetchOIDC], and [FetchOAuth2].
var (
	ErrFetchFailed      = jose.ErrFetchFailed
	ErrUnexpectedStatus = jose.ErrUnexpectedStatus
)
