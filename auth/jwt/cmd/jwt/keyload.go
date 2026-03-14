package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// loadPrivateKeys loads private key(s) from a source string.
// The source can be a file path or inline JWK/JWKS JSON.
//
// Accepts both a single JWK {"kty":..., "d":...} and a JWKS {"keys":[...]}.
func loadPrivateKeys(source string) ([]jwk.PrivateKey, error) {
	data, err := readSource(source)
	if err != nil {
		return nil, err
	}

	// Try as single private key JWK.
	var pk jwk.PrivateKey
	if err := json.Unmarshal(data, &pk); err == nil {
		return []jwk.PrivateKey{pk}, nil
	}

	// Try as JWKS with private keys.
	var rawKeys struct {
		Keys []json.RawMessage `json:"keys"`
	}
	if err := json.Unmarshal(data, &rawKeys); err == nil && len(rawKeys.Keys) > 0 {
		var keys []jwk.PrivateKey
		for i, raw := range rawKeys.Keys {
			var k jwk.PrivateKey
			if err := json.Unmarshal(raw, &k); err != nil {
				return nil, fmt.Errorf("key[%d]: %w", i, err)
			}
			keys = append(keys, k)
		}
		return keys, nil
	}

	return nil, fmt.Errorf("no private key found in source (missing \"d\" field?)")
}

// loadPublicKeys loads public key(s) from a source string.
// The source can be a URL (https://), a file path, or inline JWK/JWKS JSON.
//
// Accepts both a single JWK {"kty":...} and a JWKS {"keys":[...]}.
func loadPublicKeys(source string) ([]jwk.PublicKey, error) {
	// URL: fetch remotely.
	if strings.HasPrefix(source, "https://") || strings.HasPrefix(source, "http://") {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		keys, _, err := jwk.FetchURL(ctx, source, nil)
		if err != nil {
			return nil, fmt.Errorf("fetch keys from %s: %w", source, err)
		}
		return keys, nil
	}

	data, err := readSource(source)
	if err != nil {
		return nil, err
	}

	// Try as single public key JWK.
	var pk jwk.PublicKey
	if err := json.Unmarshal(data, &pk); err == nil && pk.CryptoPublicKey != nil {
		return []jwk.PublicKey{pk}, nil
	}

	// Try as JWKS.
	var jwks jwk.JWKs
	if err := json.Unmarshal(data, &jwks); err == nil && len(jwks.Keys) > 0 {
		return jwks.Keys, nil
	}

	return nil, fmt.Errorf("no public key found in source")
}

// loadPublicKeysFromPrivate loads private keys and derives public keys from them.
func loadPublicKeysFromPrivate(source string) ([]jwk.PublicKey, error) {
	privKeys, err := loadPrivateKeys(source)
	if err != nil {
		return nil, err
	}
	pubs := make([]jwk.PublicKey, len(privKeys))
	for i := range privKeys {
		pubs[i] = *privKeys[i].PublicKey()
	}
	return pubs, nil
}

// readSource reads data from a source string — either a file path or inline JSON.
func readSource(source string) ([]byte, error) {
	// If it looks like JSON (starts with '{' or '['), treat as inline.
	trimmed := strings.TrimSpace(source)
	if len(trimmed) > 0 && (trimmed[0] == '{' || trimmed[0] == '[') {
		return []byte(trimmed), nil
	}

	// Otherwise treat as file path.
	data, err := os.ReadFile(source)
	if err != nil {
		return nil, fmt.Errorf("read key file %q: %w", source, err)
	}
	return data, nil
}
