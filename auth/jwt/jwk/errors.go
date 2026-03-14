// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwk

import (
	"errors"
	"fmt"

	"github.com/therootcompany/golib/auth/jwt/jose"
)

// Key parsing errors — returned by [PublicKey.UnmarshalJSON],
// [PrivateKey.UnmarshalJSON], and [ReadFile].
var (
	// ErrInvalidKey is the broad category for any key that cannot be
	// decoded or fails validation. More specific sentinels below wrap it.
	ErrInvalidKey = errors.New("invalid key")

	// ErrUnsupportedKeyType indicates an unrecognized JWK "kty" value.
	// Re-exported from [jose] so jwt, jwk, and internal/jwa share one sentinel.
	ErrUnsupportedKeyType = jose.ErrUnsupportedKeyType

	// ErrUnsupportedCurve indicates an unrecognized JWK "crv" value.
	// Re-exported from [jose] so jwt, jwk, and internal/jwa share one sentinel.
	ErrUnsupportedCurve = jose.ErrUnsupportedCurve

	// ErrKeyTooSmall indicates a key that does not meet the minimum size.
	ErrKeyTooSmall = fmt.Errorf("%w: key too small", ErrInvalidKey)

	// ErrMissingKeyData indicates required key material is absent.
	ErrMissingKeyData = fmt.Errorf("%w: missing key data", ErrInvalidKey)
)

// Fetch errors — returned by [FetchURL], [FetchOIDC], and [FetchOAuth2].
var (
	ErrFetchFailed     = errors.New("fetch failed")
	ErrUnexpectedStatus = fmt.Errorf("%w: unexpected status", ErrFetchFailed)
)
