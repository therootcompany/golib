// Package jose holds sentinel errors shared across the jwt, jwk, and
// internal jwa packages. It is the leaf of the dependency graph (no
// imports of its siblings), so every package in the module can import
// it without creating cycles.
//
// This package is intentionally small. If more shared types or
// constants emerge, they belong here; package-specific errors stay in
// their own packages.
package jose

import "errors"

// Key type / curve errors — shared by jwt, jwk, and internal/jwa.
var (
	// ErrUnsupportedKeyType indicates a key type that is not supported
	// for the requested operation (signing, verification, encoding, etc.).
	ErrUnsupportedKeyType = errors.New("unsupported key type")

	// ErrUnsupportedCurve indicates an elliptic curve that is not
	// recognized or supported (e.g., an unknown JWK "crv" value).
	ErrUnsupportedCurve = errors.New("unsupported curve")
)
