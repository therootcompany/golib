// Package josert_test verifies interoperability between this library and
// github.com/go-jose/go-jose/v4 (JWS, JWK, JWT). It covers sign/verify,
// JWK serialization, thumbprint consistency, JWKS, audience, custom claims,
// NumericDate precision, and stress tests.
package josert_test

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jwk"
	"github.com/therootcompany/golib/auth/jwt/tests/testkeys"
)

// joseAlg maps our algorithm name to a go-jose SignatureAlgorithm constant.
func joseAlg(name string) jose.SignatureAlgorithm {
	switch name {
	case "EdDSA":
		return jose.EdDSA
	case "ES256":
		return jose.ES256
	case "ES384":
		return jose.ES384
	case "ES512":
		return jose.ES512
	case "RS256":
		return jose.RS256
	}
	panic("unknown alg: " + name)
}

// --- helpers ---

func assertOurSignGoJoseVerify(t *testing.T, ks testkeys.KeySet, sub string) {
	t.Helper()

	signer, err := jwt.NewSigner([]jwk.PrivateKey{ks.PrivKey})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tokenStr, err := signer.SignToString(testkeys.TestClaims(sub))
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	// Parse and verify with go-jose.
	tok, err := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{joseAlg(ks.AlgName)})
	if err != nil {
		t.Fatalf("go-jose ParseSigned: %v", err)
	}

	var claims josejwt.Claims
	if err := tok.Claims(ks.RawPub, &claims); err != nil {
		t.Fatalf("go-jose Claims: %v", err)
	}
	if claims.Subject != sub {
		t.Errorf("sub: got %q, want %q", claims.Subject, sub)
	}
	if claims.Issuer != "https://example.com" {
		t.Errorf("iss: got %q, want %q", claims.Issuer, "https://example.com")
	}
}

func assertGoJoseSignOurVerify(t *testing.T, ks testkeys.KeySet, sub string) {
	t.Helper()

	// Use JSONWebKey wrapper to get kid in the JWS header.
	sigKey := jose.SigningKey{
		Algorithm: joseAlg(ks.AlgName),
		Key: jose.JSONWebKey{
			Key:   ks.RawPriv,
			KeyID: ks.KID,
		},
	}
	joseSigner, err := jose.NewSigner(sigKey, nil)
	if err != nil {
		t.Fatalf("go-jose NewSigner: %v", err)
	}

	now := time.Now()
	claims := josejwt.Claims{
		Issuer:   "https://example.com",
		Subject:  sub,
		Expiry:   josejwt.NewNumericDate(now.Add(time.Hour)),
		IssuedAt: josejwt.NewNumericDate(now),
	}
	tokenStr, err := josejwt.Signed(joseSigner).Claims(claims).Serialize()
	if err != nil {
		t.Fatalf("go-jose Serialize: %v", err)
	}

	verifier := jwt.New([]jwk.PublicKey{ks.PubKey})
	verifiedJWS, err := verifier.VerifyJWT(tokenStr)
	if err != nil {
		t.Fatalf("our verify: %v", err)
	}

	var decoded jwt.IDTokenClaims
	if err := jwt.UnmarshalClaims(verifiedJWS, &decoded); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}
	if decoded.Sub != sub {
		t.Errorf("sub: got %q, want %q", decoded.Sub, sub)
	}
}

// --- Our sign, go-jose verify (all algorithms) ---

func TestOurSignGoJoseVerify_EdDSA(t *testing.T) {
	assertOurSignGoJoseVerify(t, testkeys.GenerateEdDSA("k1"), "user-eddsa")
}

func TestOurSignGoJoseVerify_ES256(t *testing.T) {
	assertOurSignGoJoseVerify(t, testkeys.GenerateES256("k1"), "user-es256")
}

func TestOurSignGoJoseVerify_ES384(t *testing.T) {
	assertOurSignGoJoseVerify(t, testkeys.GenerateES384("k1"), "user-es384")
}

func TestOurSignGoJoseVerify_ES512(t *testing.T) {
	assertOurSignGoJoseVerify(t, testkeys.GenerateES512("k1"), "user-es512")
}

func TestOurSignGoJoseVerify_RS256(t *testing.T) {
	assertOurSignGoJoseVerify(t, testkeys.GenerateRS256("k1"), "user-rs256")
}

// --- go-jose sign, our verify (all algorithms) ---

func TestGoJoseSignOurVerify_EdDSA(t *testing.T) {
	assertGoJoseSignOurVerify(t, testkeys.GenerateEdDSA("k1"), "user-eddsa")
}

func TestGoJoseSignOurVerify_ES256(t *testing.T) {
	assertGoJoseSignOurVerify(t, testkeys.GenerateES256("k1"), "user-es256")
}

func TestGoJoseSignOurVerify_ES384(t *testing.T) {
	assertGoJoseSignOurVerify(t, testkeys.GenerateES384("k1"), "user-es384")
}

func TestGoJoseSignOurVerify_ES512(t *testing.T) {
	assertGoJoseSignOurVerify(t, testkeys.GenerateES512("k1"), "user-es512")
}

func TestGoJoseSignOurVerify_RS256(t *testing.T) {
	assertGoJoseSignOurVerify(t, testkeys.GenerateRS256("k1"), "user-rs256")
}

// --- JWK serialization interop ---

func TestJWKInterop_OurJSONToGoJose(t *testing.T) {
	for _, ag := range testkeys.AllAlgorithms() {
		t.Run(ag.Name+"_Public", func(t *testing.T) {
			ks := ag.Generate("jwk-" + ag.Name)

			// Marshal our public key to JSON.
			ourJSON, err := json.Marshal(ks.PubKey)
			if err != nil {
				t.Fatalf("marshal our pubkey: %v", err)
			}

			// Parse with go-jose.
			var joseKey jose.JSONWebKey
			if err := json.Unmarshal(ourJSON, &joseKey); err != nil {
				t.Fatalf("go-jose unmarshal from our JSON: %v", err)
			}

			// Verify a token signed by us, using the go-jose-parsed key.
			signer, err := jwt.NewSigner([]jwk.PrivateKey{ks.PrivKey})
			if err != nil {
				t.Fatal(err)
			}
			tokenStr, err := signer.SignToString(testkeys.TestClaims("jwk-interop"))
			if err != nil {
				t.Fatal(err)
			}

			tok, err := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{joseAlg(ks.AlgName)})
			if err != nil {
				t.Fatal(err)
			}
			var claims josejwt.Claims
			if err := tok.Claims(joseKey.Key, &claims); err != nil {
				t.Fatalf("go-jose verify with our-JSON-parsed key: %v", err)
			}
		})

		t.Run(ag.Name+"_Private", func(t *testing.T) {
			ks := ag.Generate("jwk-priv-" + ag.Name)

			// Marshal our private key to JSON.
			ourJSON, err := json.Marshal(&ks.PrivKey)
			if err != nil {
				t.Fatalf("marshal our privkey: %v", err)
			}

			// Parse with go-jose.
			var joseKey jose.JSONWebKey
			if err := json.Unmarshal(ourJSON, &joseKey); err != nil {
				t.Fatalf("go-jose unmarshal from our private JSON: %v", err)
			}

			// Sign with the go-jose-parsed key, verify with our lib.
			joseKey.KeyID = ks.KID
			sigKey := jose.SigningKey{
				Algorithm: joseAlg(ks.AlgName),
				Key:       joseKey,
			}
			joseSigner, err := jose.NewSigner(sigKey, nil)
			if err != nil {
				t.Fatal(err)
			}
			claims := josejwt.Claims{
				Subject: "jwk-priv-interop",
				Expiry:  josejwt.NewNumericDate(time.Now().Add(time.Hour)),
			}
			tokenStr, err := josejwt.Signed(joseSigner).Claims(claims).Serialize()
			if err != nil {
				t.Fatalf("go-jose sign with our-JSON-parsed key: %v", err)
			}

			verifier := jwt.New([]jwk.PublicKey{ks.PubKey})
			if _, err := verifier.VerifyJWT(tokenStr); err != nil {
				t.Fatalf("our verify: %v", err)
			}
		})
	}
}

func TestJWKInterop_GoJoseJSONToOur(t *testing.T) {
	for _, ag := range testkeys.AllAlgorithms() {
		t.Run(ag.Name, func(t *testing.T) {
			ks := ag.Generate("jose-to-our-" + ag.Name)

			// Create go-jose JWK and serialize.
			joseKey := jose.JSONWebKey{
				Key:       ks.RawPub,
				KeyID:     ks.KID,
				Algorithm: ks.AlgName,
				Use:       "sig",
			}
			joseJSON, err := json.Marshal(joseKey)
			if err != nil {
				t.Fatalf("marshal go-jose key: %v", err)
			}

			// Parse with our library.
			var recovered jwk.PublicKey
			if err := json.Unmarshal(joseJSON, &recovered); err != nil {
				t.Fatalf("our unmarshal of go-jose JSON: %v", err)
			}

			// Sign with our signer, verify with the recovered key.
			signer, err := jwt.NewSigner([]jwk.PrivateKey{ks.PrivKey})
			if err != nil {
				t.Fatal(err)
			}
			tokenStr, err := signer.SignToString(testkeys.TestClaims("jose-json"))
			if err != nil {
				t.Fatal(err)
			}
			verifier := jwt.New([]jwk.PublicKey{recovered})
			if _, err := verifier.VerifyJWT(tokenStr); err != nil {
				t.Fatalf("verify with go-jose-JSON-parsed key: %v", err)
			}
		})
	}
}

// --- Thumbprint consistency (RFC 7638) ---

func TestThumbprintConsistency_GoJose(t *testing.T) {
	for _, ag := range testkeys.AllAlgorithms() {
		t.Run(ag.Name, func(t *testing.T) {
			ks := ag.Generate("thumb-" + ag.Name)

			// Our thumbprint (returns base64url string).
			ourThumb, err := ks.PubKey.Thumbprint()
			if err != nil {
				t.Fatalf("our Thumbprint: %v", err)
			}

			// go-jose thumbprint (returns raw bytes).
			joseKey := jose.JSONWebKey{Key: ks.RawPub}
			joseRaw, err := joseKey.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatalf("go-jose Thumbprint: %v", err)
			}
			joseThumb := base64.RawURLEncoding.EncodeToString(joseRaw)

			if ourThumb != joseThumb {
				t.Errorf("thumbprint mismatch:\n  ours:    %s\n  go-jose: %s", ourThumb, joseThumb)
			}
		})
	}
}

// --- JWKS interop ---

func TestJWKSInterop_OurToGoJose(t *testing.T) {
	// Build a signer with all 5 key types.
	var keys []jwk.PrivateKey
	var sets []testkeys.KeySet
	for _, ag := range testkeys.AllAlgorithms() {
		ks := ag.Generate("jwks-" + ag.Name)
		keys = append(keys, ks.PrivKey)
		sets = append(sets, ks)
	}
	signer, err := jwt.NewSigner(keys)
	if err != nil {
		t.Fatal(err)
	}

	// Serialize our JWKS.
	jwksData, err := json.Marshal(&signer)
	if err != nil {
		t.Fatal(err)
	}

	// Parse with go-jose.
	var joseJWKS jose.JSONWebKeySet
	if err := json.Unmarshal(jwksData, &joseJWKS); err != nil {
		t.Fatalf("go-jose unmarshal JWKS: %v", err)
	}
	if len(joseJWKS.Keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(joseJWKS.Keys))
	}

	// Sign tokens with each key and verify with the go-jose-parsed set.
	for i, ks := range sets {
		tokenStr, err := signer.SignToString(testkeys.TestClaims(fmt.Sprintf("jwks-%d", i)))
		if err != nil {
			t.Fatalf("sign[%d]: %v", i, err)
		}

		tok, err := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{joseAlg(ks.AlgName)})
		if err != nil {
			t.Errorf("parse[%d] (%s): %v", i, ks.AlgName, err)
			continue
		}
		// Find the matching key from the parsed JWKS.
		matching := joseJWKS.Key(ks.KID)
		if len(matching) == 0 {
			t.Errorf("no key found for kid %q", ks.KID)
			continue
		}
		var claims josejwt.Claims
		if err := tok.Claims(matching[0].Key, &claims); err != nil {
			t.Errorf("go-jose verify[%d] (%s) with parsed JWKS: %v", i, ks.AlgName, err)
		}
	}
}

func TestJWKSInterop_GoJoseToOur(t *testing.T) {
	// Build a go-jose key set.
	var joseJWKS jose.JSONWebKeySet
	var sets []testkeys.KeySet
	for _, ag := range testkeys.AllAlgorithms() {
		ks := ag.Generate("jose-jwks-" + ag.Name)
		sets = append(sets, ks)
		joseJWKS.Keys = append(joseJWKS.Keys, jose.JSONWebKey{
			Key:       ks.RawPub,
			KeyID:     ks.KID,
			Algorithm: ks.AlgName,
			Use:       "sig",
		})
	}

	// Serialize go-jose JWKS.
	jwksData, err := json.Marshal(joseJWKS)
	if err != nil {
		t.Fatal(err)
	}

	// Parse with our library.
	var ourJWKS jwk.JWKs
	if err := json.Unmarshal(jwksData, &ourJWKS); err != nil {
		t.Fatalf("our unmarshal of go-jose JWKS: %v", err)
	}
	if len(ourJWKS.Keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(ourJWKS.Keys))
	}

	verifier := jwt.New(ourJWKS.Keys)

	// Sign tokens with go-jose, verify with our library.
	for _, ks := range sets {
		sigKey := jose.SigningKey{
			Algorithm: joseAlg(ks.AlgName),
			Key: jose.JSONWebKey{
				Key:   ks.RawPriv,
				KeyID: ks.KID,
			},
		}
		joseSigner, err := jose.NewSigner(sigKey, nil)
		if err != nil {
			t.Fatalf("go-jose signer %s: %v", ks.AlgName, err)
		}
		claims := josejwt.Claims{
			Subject: "jose-to-our",
			Expiry:  josejwt.NewNumericDate(time.Now().Add(time.Hour)),
		}
		tokenStr, err := josejwt.Signed(joseSigner).Claims(claims).Serialize()
		if err != nil {
			t.Fatalf("go-jose sign %s: %v", ks.AlgName, err)
		}
		if _, err := verifier.VerifyJWT(tokenStr); err != nil {
			t.Errorf("our verify %s from go-jose JWKS: %v", ks.AlgName, err)
		}
	}
}

// --- Audience interop ---

func TestAudienceStringInterop_GoJose(t *testing.T) {
	ks := testkeys.GenerateEdDSA("aud-test")

	// Our library: single aud marshals as plain string "single-aud".
	signer, err := jwt.NewSigner([]jwk.PrivateKey{ks.PrivKey})
	if err != nil {
		t.Fatal(err)
	}
	claims := testkeys.AudienceClaims("aud-str", jwt.Audience{"single-aud"})
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("go-jose parse: %v", err)
	}
	var joseClaims josejwt.Claims
	if err := tok.Claims(ks.RawPub, &joseClaims); err != nil {
		t.Fatalf("go-jose Claims: %v", err)
	}
	if len(joseClaims.Audience) != 1 || joseClaims.Audience[0] != "single-aud" {
		t.Errorf("aud: got %v, want [single-aud]", joseClaims.Audience)
	}

	// Reverse: go-jose signs with single aud, our library parses.
	sigKey := jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       jose.JSONWebKey{Key: ks.RawPriv, KeyID: ks.KID},
	}
	joseSigner, _ := jose.NewSigner(sigKey, nil)
	jClaims := josejwt.Claims{
		Subject:  "aud-str-rev",
		Audience: josejwt.Audience{"single-aud"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	joseToken, _ := josejwt.Signed(joseSigner).Claims(jClaims).Serialize()

	verifier := jwt.New([]jwk.PublicKey{ks.PubKey})
	verifiedJWS, err := verifier.VerifyJWT(joseToken)
	if err != nil {
		t.Fatal(err)
	}
	var decoded jwt.IDTokenClaims
	jwt.UnmarshalClaims(verifiedJWS, &decoded)
	if len(decoded.Aud) == 0 || decoded.Aud[0] != "single-aud" {
		t.Errorf("reverse aud: got %v, want [single-aud]", decoded.Aud)
	}
}

func TestAudienceArrayInterop_GoJose(t *testing.T) {
	ks := testkeys.GenerateEdDSA("aud-arr")

	signer, _ := jwt.NewSigner([]jwk.PrivateKey{ks.PrivKey})
	claims := testkeys.AudienceClaims("aud-arr", jwt.Audience{"aud1", "aud2"})
	tokenStr, _ := signer.SignToString(claims)

	tok, err := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("go-jose parse: %v", err)
	}
	var joseClaims josejwt.Claims
	if err := tok.Claims(ks.RawPub, &joseClaims); err != nil {
		t.Fatal(err)
	}
	if len(joseClaims.Audience) != 2 || joseClaims.Audience[0] != "aud1" || joseClaims.Audience[1] != "aud2" {
		t.Errorf("aud: got %v, want [aud1 aud2]", joseClaims.Audience)
	}
}

// --- Custom claims interop ---

func TestCustomClaimsInterop_GoJose(t *testing.T) {
	ks := testkeys.GenerateEdDSA("custom")
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{ks.PrivKey})
	claims := &testkeys.CustomClaims{
		IDTokenClaims: *testkeys.TestClaims("custom-user"),
		Email:         "user@example.com",
		Roles:         []string{"admin", "editor"},
		Metadata:      map[string]string{"team": "platform"},
	}
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatalf("go-jose parse: %v", err)
	}

	// go-jose extracts into an arbitrary struct.
	var extracted struct {
		josejwt.Claims
		Email    string            `json:"email"`
		Roles    []string          `json:"roles"`
		Metadata map[string]string `json:"metadata"`
	}
	if err := tok.Claims(ks.RawPub, &extracted); err != nil {
		t.Fatalf("go-jose Claims: %v", err)
	}
	if extracted.Email != "user@example.com" {
		t.Errorf("email: got %q, want %q", extracted.Email, "user@example.com")
	}
	if len(extracted.Roles) != 2 || extracted.Roles[0] != "admin" {
		t.Errorf("roles: got %v, want [admin editor]", extracted.Roles)
	}
	if extracted.Metadata["team"] != "platform" {
		t.Errorf("metadata.team: got %v, want %q", extracted.Metadata["team"], "platform")
	}
}

// --- NumericDate precision ---

func TestNumericDatePrecision_GoJose(t *testing.T) {
	ks := testkeys.GenerateEdDSA("nd")

	// Use fixed future timestamps to test precision without triggering
	// expiration validation. 2000000000 = 2033-05-18.
	var wantExp int64 = 2000000000
	var wantIat int64 = 1999999000
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "numdate",
		Exp: wantExp,
		Iat: wantIat,
	}
	signer, _ := jwt.NewSigner([]jwk.PrivateKey{ks.PrivKey})
	tokenStr, _ := signer.SignToString(claims)

	tok, err := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.EdDSA})
	if err != nil {
		t.Fatal(err)
	}
	var joseClaims josejwt.Claims
	if err := tok.Claims(ks.RawPub, &joseClaims); err != nil {
		t.Fatal(err)
	}
	if joseClaims.Expiry.Time().Unix() != wantExp {
		t.Errorf("exp: got %d, want %d", joseClaims.Expiry.Time().Unix(), wantExp)
	}
	if joseClaims.IssuedAt.Time().Unix() != wantIat {
		t.Errorf("iat: got %d, want %d", joseClaims.IssuedAt.Time().Unix(), wantIat)
	}

	// Reverse: go-jose signs with specific times, our library reads.
	var wantExp2 int64 = 2100000000
	var wantIat2 int64 = 2099999000
	sigKey := jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       jose.JSONWebKey{Key: ks.RawPriv, KeyID: ks.KID},
	}
	joseSigner, _ := jose.NewSigner(sigKey, nil)
	jClaims := josejwt.Claims{
		Subject:  "numdate-rev",
		Expiry:   josejwt.NewNumericDate(time.Unix(wantExp2, 0)),
		IssuedAt: josejwt.NewNumericDate(time.Unix(wantIat2, 0)),
	}
	joseToken, _ := josejwt.Signed(joseSigner).Claims(jClaims).Serialize()

	verifier := jwt.New([]jwk.PublicKey{ks.PubKey})
	verifiedJWS, _ := verifier.VerifyJWT(joseToken)
	var decoded jwt.IDTokenClaims
	jwt.UnmarshalClaims(verifiedJWS, &decoded)
	if decoded.Exp != wantExp2 {
		t.Errorf("rev exp: got %d, want %d", decoded.Exp, wantExp2)
	}
	if decoded.Iat != wantIat2 {
		t.Errorf("rev iat: got %d, want %d", decoded.Iat, wantIat2)
	}
}

// --- Stress tests ---

func TestStress_GoJose(t *testing.T) {
	for _, ag := range testkeys.AllAlgorithms() {
		ag := ag
		t.Run(ag.Name, func(t *testing.T) {
			t.Parallel()
			n := 1000
			if testing.Short() && ag.Name == "RS256" {
				n = 10
			}
			for i := range n {
				ks := ag.Generate(fmt.Sprintf("s%d", i))
				sub := fmt.Sprintf("stress-%d", i)

				// Our sign, go-jose verify.
				signer, err := jwt.NewSigner([]jwk.PrivateKey{ks.PrivKey})
				if err != nil {
					t.Fatalf("iter %d: NewSigner: %v", i, err)
				}
				tokenStr, err := signer.SignToString(testkeys.TestClaims(sub))
				if err != nil {
					t.Fatalf("iter %d: SignToString: %v", i, err)
				}
				tok, err := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{joseAlg(ks.AlgName)})
				if err != nil {
					t.Fatalf("iter %d: go-jose parse: %v", i, err)
				}
				var claims josejwt.Claims
				if err := tok.Claims(ks.RawPub, &claims); err != nil {
					t.Fatalf("iter %d: go-jose verify: %v", i, err)
				}

				// go-jose sign, our verify.
				sigKey := jose.SigningKey{
					Algorithm: joseAlg(ks.AlgName),
					Key:       jose.JSONWebKey{Key: ks.RawPriv, KeyID: ks.KID},
				}
				joseSigner, err := jose.NewSigner(sigKey, nil)
				if err != nil {
					t.Fatalf("iter %d: go-jose NewSigner: %v", i, err)
				}
				jClaims := josejwt.Claims{
					Subject: sub,
					Expiry:  josejwt.NewNumericDate(time.Now().Add(time.Hour)),
				}
				joseToken, err := josejwt.Signed(joseSigner).Claims(jClaims).Serialize()
				if err != nil {
					t.Fatalf("iter %d: go-jose sign: %v", i, err)
				}
				verifier := jwt.New([]jwk.PublicKey{ks.PubKey})
				if _, err := verifier.VerifyJWT(joseToken); err != nil {
					t.Fatalf("iter %d: our verify: %v", i, err)
				}
			}
		})
	}
}
