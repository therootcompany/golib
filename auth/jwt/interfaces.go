// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

// jwtsigner is the interface for signing JWTs.
//
// Implementations include [*Signer] and [*HMACSigner]. Use this interface when
// you want to accept any JWT signer (e.g., for testing with a mock, or for
// future algorithm variants).
type jwtsigner[T jwtverifier] interface {
	// SignJWT signs a JWT in-place. Sets the alg header and computes
	// the HMAC signature over the protected.payload input.
	SignJWT(jws SignableJWT) error

	// SignRaw signs an arbitrary protected header and payload, returning
	// the result as a [*jwt.RawJWT] suitable for json.Marshal (flattened
	// JWS) or jwt.Encode (compact serialization).
	//
	// Unlike SignJWT, SignRaw does not set or validate the KID field —
	// the caller controls it entirely. The alg field is always set from
	// the signer's algorithm. If hdr already has a non-empty Alg that
	// conflicts with the signer's algorithm, SignRaw returns an error.
	//
	// payload is the raw bytes to encode as the JWS payload. A nil
	// payload produces an empty payload segment (used by ACME POST-as-GET).
	SignRaw(hdr Header, payload []byte) (*RawJWT, error)

	// SignToString creates and signs a JWT from claims and returns the
	// compact token string (header.payload.signature).
	SignToString(claims Claims) (string, error)

	// HMACVerifier returns a new [*HMACVerifier] for verifying tokens signed
	// by this signer.
	Verifier() T
}

// Verifier is the interface for verifying JWT signatures with HMAC.
//
// Implementations include [*HMACVerifier]. Use this interface when you want
// to accept any HMAC-based verifier (e.g., for testing with a mock).
type jwtverifier interface {
	// Verify checks the signature of an already-decoded [*jwt.JWT].
	//
	// Returns nil on success, a descriptive error on failure. Claim
	// values (iss, aud, exp, etc.) are NOT checked — call
	// jwt.Validator.Validate on the unmarshalled claims after verifying.
	Verify(jws VerifiableJWT) error
}
