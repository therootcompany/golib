package jwt

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"encoding/base64"
	"math/big"
	"testing"
)

// TestDecodeJWKsJSON tests parsing a specific set of ECDSA P-256 JWKS
func TestDecodeJWKJSON(t *testing.T) {
	// Create a temporary file with the test JWKS
	kid := "KGx1KSmDRd_dwuwmZmWiEsl9Dh4c5dQtFLLtTl-UvlI"
	jwkX := "WVBcjUpllgeGbGavZ9Bbq4ps3Zk73mgRRPpbfebkC3U"
	jwkY := "aTmrRia2eiJsJwzuj7DIUVmMVGrjEzQJkxxiQMgVLOw"
	jwkUse := "sig"
	jwksJSON := []byte(`{"keys":[{"kty":"EC","crv":"P-256","x":"` + jwkX + `","y":"` + jwkY + `","kid":"` + kid + `","use":"` + jwkUse + `"}]}`)

	// Decode from bytes to JSON to Public JWKs
	keys, err := UnmarshalPublicJWKs(jwksJSON)
	if err != nil {
		t.Fatalf("ReadJWKs failed: %v", err)
	}

	// Verify results
	if len(keys) != 1 {
		t.Errorf("Expected 1 key, got %d", len(keys))
	}

	key := keys[0]
	if key.KID != kid {
		t.Errorf("Expected KID '%s', got '%s'", kid, key.KID)
	}
	if key.Use != jwkUse {
		t.Errorf("Expected Use 'sig', got '%s'", key.Use)
	}

	expectedX, _ := base64.RawURLEncoding.DecodeString(jwkX)
	expectedY, _ := base64.RawURLEncoding.DecodeString(jwkY)

	// Verify Equal method
	sameKey := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(expectedX),
		Y:     new(big.Int).SetBytes(expectedY),
	}
	if !key.Equal(sameKey) {
		t.Errorf("Equal method failed: key should equal itself")
	}
}
