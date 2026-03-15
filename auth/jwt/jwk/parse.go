// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwk

import "encoding/json"

// ParsePublicJWK parses a single JWK JSON object into a [PublicKey].
// KID is auto-computed from the RFC 7638 thumbprint if not present in the JWK.
func ParsePublicJWK(data []byte) (*PublicKey, error) {
	var pk PublicKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, err
	}
	return &pk, nil
}

// ParsePrivateJWK parses a single JWK JSON object with private key material
// into a [PrivateKey]. The "d" field must be present.
// KID is auto-computed from the RFC 7638 thumbprint if not present in the JWK.
func ParsePrivateJWK(data []byte) (*PrivateKey, error) {
	var pk PrivateKey
	if err := json.Unmarshal(data, &pk); err != nil {
		return nil, err
	}
	return &pk, nil
}

// ParsePublicJWKs parses a JWKS document ({"keys": [...]}) into a [JWKs].
// Each key's KID is auto-computed from the RFC 7638 thumbprint if not present.
func ParsePublicJWKs(data []byte) (JWKs, error) {
	var jwks JWKs
	if err := json.Unmarshal(data, &jwks); err != nil {
		return JWKs{}, err
	}
	return jwks, nil
}
