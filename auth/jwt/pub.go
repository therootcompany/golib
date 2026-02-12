package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"time"
)

type PublicKey interface {
	Equal(x crypto.PublicKey) bool
}

// PublicJWK represents a parsed public key (RSA or ECDSA)
type PublicJWK struct {
	PublicKey
	KID string
	Use string
}

// PublicJWKJSON represents a JSON Web Key as defined in the provided code
type PublicJWKJSON struct {
	Kty string `json:"kty"`
	KID string `json:"kid"`
	N   string `json:"n,omitempty"` // RSA modulus
	E   string `json:"e,omitempty"` // RSA exponent
	Crv string `json:"crv,omitempty"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	Use string `json:"use,omitempty"`
}

type JWKsJSON struct {
	Keys []PublicJWKJSON `json:"keys"`
}

func UnmarshalPublicJWKs(data []byte) ([]PublicJWK, error) {
	var jwks JWKsJSON
	if err := json.Unmarshal(data, &jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}

	pubkeys, err := DecodePublicJWKsJSON(jwks)
	if err != nil {
		return nil, err
	}

	return pubkeys, nil
}

func DecodePublicJWKs(r io.Reader) ([]PublicJWK, error) {
	var jwks JWKsJSON

	if err := json.NewDecoder(r).Decode(&jwks); err != nil {
		return nil, fmt.Errorf("failed to parse JWKS JSON: %w", err)
	}

	pubkeys, err := DecodePublicJWKsJSON(jwks)
	if err != nil {
		return nil, err
	}

	return pubkeys, nil
}

// DecodePublicJWKsJSON parses JWKS from a Reader
func DecodePublicJWKsJSON(jwks JWKsJSON) ([]PublicJWK, error) {
	// Process keys
	var publicKeys []PublicJWK
	for _, jwk := range jwks.Keys {
		publicKey, err := DecodePublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse public jwk '%s': %w", jwk.KID, err)
		}
		publicKeys = append(publicKeys, *publicKey)
	}

	if len(publicKeys) == 0 {
		return nil, fmt.Errorf("no valid RSA or ECDSA keys found")
	}

	return publicKeys, nil
}

// DecodePublicJWK parses JWKS from a Reader
func DecodePublicJWK(jwk PublicJWKJSON) (*PublicJWK, error) {
	switch jwk.Kty {
	case "RSA":
		key, err := decodeRSAPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse RSA key '%s': %w", jwk.KID, err)
		}
		// Ensure RSA key meets minimum size requirement
		if key.Size() < 128 { // 1024 bits / 8 = 128 bytes
			return nil, fmt.Errorf("RSA key '%s' too small: %d bytes", jwk.KID, key.Size())
		}
		return &PublicJWK{PublicKey: key, KID: jwk.KID, Use: jwk.Use}, nil

	case "EC":
		key, err := decodeECDSAPublicJWK(jwk)
		if err != nil {
			return nil, fmt.Errorf("failed to parse EC key '%s': %w", jwk.KID, err)
		}
		return &PublicJWK{KID: jwk.KID, PublicKey: key, Use: jwk.Use}, nil

	default:
		return nil, fmt.Errorf("failed to parse unknown key type '%s': %s", jwk.Kty, jwk.KID)
	}
}

// ReadPublicJWKs reads and parses JWKS from a file
func ReadPublicJWKs(filePath string) ([]PublicJWK, error) {
	file, err := os.Open(filePath)
	if err != nil {
		return nil, fmt.Errorf("failed to open JWKS file '%s': %w", filePath, err)
	}
	defer func() { _ = file.Close() }()

	return DecodePublicJWKs(file)
}

// FetchPublicJWKs retrieves and parses JWKS from a given URL
func FetchPublicJWKs(url string) ([]PublicJWK, error) {
	// Set up HTTP client with timeout
	client := &http.Client{
		Timeout: 10 * time.Second,
	}

	// Make HTTP request
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch JWKS: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Check response status
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}

	return DecodePublicJWKs(resp.Body)
}

// decodeRSAPublicJWK parses an RSA public key from a JWK
func decodeRSAPublicJWK(jwk PublicJWKJSON) (*rsa.PublicKey, error) {
	n, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA modulus: %w", err)
	}
	e, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("invalid RSA exponent: %w", err)
	}

	// Convert exponent to int
	eInt := new(big.Int).SetBytes(e).Int64()
	if eInt > int64(^uint(0)>>1) || eInt < 0 {
		return nil, fmt.Errorf("RSA exponent too large or negative")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(n),
		E: int(eInt),
	}, nil
}

// decodeECDSAPublicJWK parses an ECDSA public key from a JWK
func decodeECDSAPublicJWK(jwk PublicJWKJSON) (*ecdsa.PublicKey, error) {
	x, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA X: %w", err)
	}
	y, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, fmt.Errorf("invalid ECDSA Y: %w", err)
	}

	var curve elliptic.Curve
	switch jwk.Crv {
	case "P-256":
		curve = elliptic.P256()
	case "P-384":
		curve = elliptic.P384()
	case "P-521":
		curve = elliptic.P521()
	default:
		return nil, fmt.Errorf("unsupported ECDSA curve: %s", jwk.Crv)
	}

	return &ecdsa.PublicKey{
		Curve: curve,
		X:     new(big.Int).SetBytes(x),
		Y:     new(big.Int).SetBytes(y),
	}, nil
}
