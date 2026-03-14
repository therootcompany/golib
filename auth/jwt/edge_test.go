package jwt_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jose"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// --- JWK parsing edge cases ---

func TestJWKMissingKty(t *testing.T) {
	data := []byte(`{"kid":"test"}`)
	var pk jwk.PublicKey
	err := pk.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error for missing kty")
	}
	if !errors.Is(err, jose.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got: %v", err)
	}
}

func TestJWKUnknownKty(t *testing.T) {
	data := []byte(`{"kty":"MAGIC","kid":"test"}`)
	var pk jwk.PublicKey
	err := pk.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error for unknown kty")
	}
	if !errors.Is(err, jose.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got: %v", err)
	}
}

func TestPrivateKeyMissingD(t *testing.T) {
	// Valid EC public key but no "d" field
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := jwk.PublicKey{CryptoPublicKey: &ecKey.PublicKey, KID: "test"}
	pubJSON, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}

	var pk jwk.PrivateKey
	err = pk.UnmarshalJSON(pubJSON)
	if err == nil {
		t.Fatal("expected error for missing d field")
	}
	if !errors.Is(err, jose.ErrMissingKeyData) {
		t.Fatalf("expected ErrMissingKeyData, got: %v", err)
	}
}

func TestRSAKeyTooSmall(t *testing.T) {
	// Construct a 512-bit RSA JWK directly (Go 1.24+ refuses to generate
	// small keys, so we build the JSON by hand).
	n := make([]byte, 64) // 512-bit modulus
	n[0] = 0x80           // set MSB so modulus is actually 512 bits
	data, _ := json.Marshal(map[string]string{
		"kty": "RSA",
		"kid": "small",
		"n":   base64.RawURLEncoding.EncodeToString(n),
		"e":   "AQAB",
	})

	var decoded jwk.PublicKey
	err := decoded.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error for small RSA key")
	}
	if !errors.Is(err, jose.ErrKeyTooSmall) {
		t.Fatalf("expected ErrKeyTooSmall, got: %v", err)
	}
}

func TestRSADegenerateExponent(t *testing.T) {
	tests := []struct {
		name string
		e    int
	}{
		{"exponent_0", 0},
		{"exponent_1", 1},
		{"exponent_2", 2},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build a JWK with a degenerate exponent
			n := make([]byte, 256) // 2048-bit modulus
			n[0] = 1              // non-zero MSB
			eBytes := big.NewInt(int64(tt.e)).Bytes()
			data, _ := json.Marshal(map[string]string{
				"kty": "RSA",
				"kid": "bad-e",
				"n":   base64.RawURLEncoding.EncodeToString(n),
				"e":   base64.RawURLEncoding.EncodeToString(eBytes),
			})

			var pk jwk.PublicKey
			err := pk.UnmarshalJSON(data)
			if err == nil {
				t.Fatal("expected error for degenerate RSA exponent")
			}
			if !errors.Is(err, jose.ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey, got: %v", err)
			}
		})
	}
}

func TestRSAEmptyFields(t *testing.T) {
	tests := []struct {
		name string
		jwk  map[string]string
	}{
		{"empty_n", map[string]string{"kty": "RSA", "n": "", "e": "AQAB"}},
		{"empty_e", map[string]string{"kty": "RSA", "n": "AQAB", "e": ""}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(tt.jwk)
			var pk jwk.PublicKey
			err := pk.UnmarshalJSON(data)
			if err == nil {
				t.Fatal("expected error for empty RSA field")
			}
			if !errors.Is(err, jose.ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey, got: %v", err)
			}
		})
	}
}

func TestEd25519WrongKeySize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"too_short_31", 31},
		{"too_long_33", 33},
		{"zero_length", 0},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			x := make([]byte, tt.size)
			data, _ := json.Marshal(map[string]string{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(x),
			})

			var pk jwk.PublicKey
			err := pk.UnmarshalJSON(data)
			if err == nil {
				t.Fatalf("expected error for Ed25519 key size %d", tt.size)
			}
			if !errors.Is(err, jose.ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey, got: %v", err)
			}
		})
	}
}

func TestEd25519AllZerosKey(t *testing.T) {
	// All-zeros is a valid encoding but represents a low-order point.
	// The key should parse (it's 32 bytes), and signing should work
	// but verification with the wrong key should fail.
	x := make([]byte, ed25519.PublicKeySize) // all zeros
	data, _ := json.Marshal(map[string]string{
		"kty": "OKP",
		"crv": "Ed25519",
		"kid": "zero-key",
		"x":   base64.RawURLEncoding.EncodeToString(x),
	})

	var pk jwk.PublicKey
	err := pk.UnmarshalJSON(data)
	if err != nil {
		t.Fatalf("all-zeros Ed25519 key should parse: %v", err)
	}

	// Verify with this key should reject any real signature
	realKey, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]jwk.PrivateKey{*realKey})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	// Parse and try to verify with the all-zeros key
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatal(err)
	}

	// Change the kid in the header to match our zero key
	zeroVerifier := jwt.NewVerifier([]jwk.PublicKey{pk})
	// The KID won't match, but let's verify that the system handles it
	err = zeroVerifier.Verify(jws)
	if err == nil {
		t.Fatal("expected verification to fail with wrong key")
	}
}

func TestOKPWrongCrv(t *testing.T) {
	data, _ := json.Marshal(map[string]string{
		"kty": "OKP",
		"crv": "X25519",
		"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})

	var pk jwk.PublicKey
	err := pk.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error for X25519 crv")
	}
	if !errors.Is(err, jose.ErrUnsupportedCurve) {
		t.Fatalf("expected ErrUnsupportedCurve, got: %v", err)
	}
}

func TestOKPPrivateWrongCrv(t *testing.T) {
	data, _ := json.Marshal(map[string]string{
		"kty": "OKP",
		"crv": "X25519",
		"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
		"d":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
	})

	var pk jwk.PrivateKey
	err := pk.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error for X25519 crv on private key")
	}
	if !errors.Is(err, jose.ErrUnsupportedCurve) {
		t.Fatalf("expected ErrUnsupportedCurve, got: %v", err)
	}
}

func TestECCoordinatesTooLong(t *testing.T) {
	ci := struct {
		keySize int
		crv     string
	}{32, "P-256"} // P-256 has 32-byte coordinates

	tests := []struct {
		name  string
		xSize int
		ySize int
	}{
		{"x_too_long", ci.keySize + 1, ci.keySize},
		{"y_too_long", ci.keySize, ci.keySize + 1},
		{"both_too_long", ci.keySize + 1, ci.keySize + 1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(map[string]string{
				"kty": "EC",
				"crv": ci.crv,
				"x":   base64.RawURLEncoding.EncodeToString(make([]byte, tt.xSize)),
				"y":   base64.RawURLEncoding.EncodeToString(make([]byte, tt.ySize)),
			})

			var pk jwk.PublicKey
			err := pk.UnmarshalJSON(data)
			if err == nil {
				t.Fatal("expected error for oversized EC coordinates")
			}
			if !errors.Is(err, jose.ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey, got: %v", err)
			}
		})
	}
}

func TestECUnsupportedCurve(t *testing.T) {
	data, _ := json.Marshal(map[string]string{
		"kty": "EC",
		"crv": "P-192",
		"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
		"y":   base64.RawURLEncoding.EncodeToString(make([]byte, 24)),
	})

	var pk jwk.PublicKey
	err := pk.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error for P-192 curve")
	}
	if !errors.Is(err, jose.ErrUnsupportedCurve) {
		t.Fatalf("expected ErrUnsupportedCurve, got: %v", err)
	}
}

func TestEd25519PrivateWrongSeedSize(t *testing.T) {
	tests := []struct {
		name string
		size int
	}{
		{"seed_too_short", 31},
		{"seed_too_long", 33},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(map[string]string{
				"kty": "OKP",
				"crv": "Ed25519",
				"x":   base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
				"d":   base64.RawURLEncoding.EncodeToString(make([]byte, tt.size)),
			})

			var pk jwk.PrivateKey
			err := pk.UnmarshalJSON(data)
			if err == nil {
				t.Fatalf("expected error for seed size %d", tt.size)
			}
			if !errors.Is(err, jose.ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey, got: %v", err)
			}
		})
	}
}

func TestInvalidBase64Fields(t *testing.T) {
	tests := []struct {
		name string
		jwk  map[string]string
	}{
		{"invalid_rsa_n", map[string]string{"kty": "RSA", "n": "!!!invalid!!!", "e": "AQAB"}},
		{"invalid_rsa_e", map[string]string{"kty": "RSA", "n": "AQAB", "e": "!!!"}},
		{"invalid_ec_x", map[string]string{"kty": "EC", "crv": "P-256", "x": "!!!", "y": "AAAA"}},
		{"invalid_ec_y", map[string]string{"kty": "EC", "crv": "P-256", "x": "AAAA", "y": "!!!"}},
		{"invalid_okp_x", map[string]string{"kty": "OKP", "crv": "Ed25519", "x": "!!!"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(tt.jwk)
			var pk jwk.PublicKey
			err := pk.UnmarshalJSON(data)
			if err == nil {
				t.Fatal("expected error for invalid base64")
			}
			if !errors.Is(err, jose.ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey, got: %v", err)
			}
		})
	}
}

func TestInvalidBase64PrivateFields(t *testing.T) {
	tests := []struct {
		name string
		jwk  map[string]string
	}{
		{"invalid_ec_d", map[string]string{
			"kty": "EC", "crv": "P-256",
			"x": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			"y": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			"d": "!!!invalid!!!",
		}},
		{"invalid_rsa_d", map[string]string{
			"kty": "RSA",
			"n":   base64.RawURLEncoding.EncodeToString(make([]byte, 256)),
			"e":   "AQAB",
			"d":   "!!!invalid!!!",
		}},
		{"invalid_okp_d", map[string]string{
			"kty": "OKP", "crv": "Ed25519",
			"x": base64.RawURLEncoding.EncodeToString(make([]byte, 32)),
			"d": "!!!invalid!!!",
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			data, _ := json.Marshal(tt.jwk)
			var pk jwk.PrivateKey
			err := pk.UnmarshalJSON(data)
			if err == nil {
				t.Fatal("expected error for invalid base64 in private field")
			}
			if !errors.Is(err, jose.ErrInvalidKey) {
				t.Fatalf("expected ErrInvalidKey, got: %v", err)
			}
		})
	}
}

// --- Signature verification edge cases ---

func TestVerifyWrongKeyTypeForAlg(t *testing.T) {
	// Sign with Ed25519, then try to verify with an RSA key
	// that has the same KID
	edKey, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]jwk.PrivateKey{*edKey})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	// Create an RSA key with the same KID
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub := jwk.PublicKey{
		CryptoPublicKey: &rsaKey.PublicKey,
		KID:             edKey.KID, // same KID
	}

	verifier := jwt.NewVerifier([]jwk.PublicKey{rsaPub})
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		t.Fatal(err)
	}
	err = verifier.Verify(jws)
	if err == nil {
		t.Fatal("expected error: wrong key type for EdDSA alg")
	}
	if !errors.Is(err, jose.ErrAlgConflict) {
		t.Fatalf("expected ErrAlgConflict, got: %v", err)
	}
}

func TestVerifyZeroLengthSignature(t *testing.T) {
	// Create a valid token then replace the signature with empty
	key, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}

	signer, err := jwt.NewSigner([]jwk.PrivateKey{*key})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	// Replace signature with empty
	parts := splitToken(tokenStr)
	tampered := parts[0] + "." + parts[1] + "."
	jws, err := jwt.Decode(tampered)
	if err != nil {
		t.Fatal(err)
	}

	verifier := signer.Verifier()
	err = verifier.Verify(jws)
	if err == nil {
		t.Fatal("expected error for zero-length signature")
	}
	if !errors.Is(err, jose.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}
}

func TestVerifyECDSAWrongSigLength(t *testing.T) {
	// Sign with P-256, verify with correct key but tampered sig length
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := jwk.PrivateKey{Signer: ecKey}
	signer, err := jwt.NewSigner([]jwk.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	// Replace signature with wrong-length bytes
	parts := splitToken(tokenStr)
	wrongSig := base64.RawURLEncoding.EncodeToString([]byte("short"))
	tampered := parts[0] + "." + parts[1] + "." + wrongSig

	jws, err := jwt.Decode(tampered)
	if err != nil {
		t.Fatal(err)
	}

	verifier := signer.Verifier()
	err = verifier.Verify(jws)
	if err == nil {
		t.Fatal("expected error for wrong ECDSA signature length")
	}
	if !errors.Is(err, jose.ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid, got: %v", err)
	}
}

func TestVerifyUnsupportedAlg(t *testing.T) {
	// Build a token with an unsupported alg header
	key, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]jwk.PrivateKey{*key})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper the header to use an unsupported alg
	header := map[string]string{"alg": "HS256", "kid": key.KID, "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	parts := splitToken(tokenStr)
	tampered := headerB64 + "." + parts[1] + "." + parts[2]

	jws, err := jwt.Decode(tampered)
	if err != nil {
		t.Fatal(err)
	}

	verifier := signer.Verifier()
	err = verifier.Verify(jws)
	if err == nil {
		t.Fatal("expected error for unsupported alg")
	}
	if !errors.Is(err, jose.ErrUnsupportedAlg) {
		t.Fatalf("expected ErrUnsupportedAlg, got: %v", err)
	}
}

func TestVerifyMissingKID(t *testing.T) {
	key, err := jwk.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]jwk.PrivateKey{*key})
	if err != nil {
		t.Fatal(err)
	}

	claims := goodClaims()
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		t.Fatal(err)
	}

	// Tamper header to remove kid
	header := map[string]string{"alg": "EdDSA", "typ": "JWT"}
	headerJSON, _ := json.Marshal(header)
	headerB64 := base64.RawURLEncoding.EncodeToString(headerJSON)

	parts := splitToken(tokenStr)
	tampered := headerB64 + "." + parts[1] + "." + parts[2]

	jws, err := jwt.Decode(tampered)
	if err != nil {
		t.Fatal(err)
	}

	verifier := signer.Verifier()
	err = verifier.Verify(jws)
	if err == nil {
		t.Fatal("expected error for missing kid")
	}
	if !errors.Is(err, jose.ErrMissingKID) {
		t.Fatalf("expected ErrMissingKID, got: %v", err)
	}
}

func TestDecodeEmptyToken(t *testing.T) {
	_, err := jwt.Decode("")
	if err == nil {
		t.Fatal("expected error for empty token")
	}
	if !errors.Is(err, jose.ErrMalformedToken) {
		t.Fatalf("expected ErrMalformedToken, got: %v", err)
	}
}

func TestDecodeOnePart(t *testing.T) {
	_, err := jwt.Decode("justonepart")
	if err == nil {
		t.Fatal("expected error for single-part token")
	}
	if !errors.Is(err, jose.ErrMalformedToken) {
		t.Fatalf("expected ErrMalformedToken, got: %v", err)
	}
}

func TestDecodeFourParts(t *testing.T) {
	_, err := jwt.Decode("a.b.c.d")
	if err == nil {
		t.Fatal("expected error for four-part token")
	}
	if !errors.Is(err, jose.ErrMalformedToken) {
		t.Fatalf("expected ErrMalformedToken, got: %v", err)
	}
}

// --- RSA private key edge cases ---

func TestRSAPrivateKeyTooSmall(t *testing.T) {
	// Construct a 512-bit RSA private JWK directly (Go 1.24+ refuses to
	// generate small keys).
	n := make([]byte, 64) // 512-bit modulus
	n[0] = 0x80
	d := make([]byte, 64)
	d[0] = 0x01
	data, _ := json.Marshal(map[string]string{
		"kty": "RSA",
		"kid": "small",
		"n":   base64.RawURLEncoding.EncodeToString(n),
		"e":   "AQAB",
		"d":   base64.RawURLEncoding.EncodeToString(d),
	})

	var decoded jwk.PrivateKey
	err := decoded.UnmarshalJSON(data)
	if err == nil {
		t.Fatal("expected error for small RSA private key")
	}
	if !errors.Is(err, jose.ErrKeyTooSmall) {
		t.Fatalf("expected ErrKeyTooSmall, got: %v", err)
	}
}

// --- Thumbprint edge cases ---

func TestThumbprintNilKey(t *testing.T) {
	pk := jwk.PublicKey{} // nil CryptoPublicKey
	_, err := pk.Thumbprint()
	if err == nil {
		t.Fatal("expected error for nil key thumbprint")
	}
	if !errors.Is(err, jose.ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got: %v", err)
	}
}

// splitToken splits a compact JWT into its three dot-separated parts.
func splitToken(s string) [3]string {
	var parts [3]string
	idx1 := 0
	for i, c := range s {
		if c == '.' {
			if idx1 == 0 {
				parts[0] = s[:i]
				idx1 = i + 1
			} else {
				parts[1] = s[idx1:i]
				parts[2] = s[i+1:]
				return parts
			}
		}
	}
	return parts
}
