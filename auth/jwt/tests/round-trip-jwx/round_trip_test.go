// Package jwxrt_test verifies interoperability between this library and
// github.com/lestrrat-go/jwx/v3 (JWA, JWK, JWS, JWT). It covers sign/verify,
// JWK serialization, thumbprint consistency, JWKS, audience, custom claims,
// NumericDate precision, and stress tests.
package jwxrt_test

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v3/jwa"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	"github.com/lestrrat-go/jwx/v3/jws"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/tests/testkeys"
)

var longTests = flag.Bool("long", false, "run extended stress tests (100 RSA iterations instead of 10)")

// jwxAlg maps our algorithm name to a jwx v3 SignatureAlgorithm.
func jwxAlg(name string) jwa.SignatureAlgorithm {
	switch name {
	case "EdDSA":
		return jwa.EdDSA()
	case "ES256":
		return jwa.ES256()
	case "ES384":
		return jwa.ES384()
	case "ES512":
		return jwa.ES512()
	case "RS256":
		return jwa.RS256()
	}
	panic("unknown alg: " + name)
}

// --- helpers ---

func assertOurSignJWXVerify(t *testing.T, ks testkeys.KeySet, sub string) {
	t.Helper()

	signer, err := jwt.NewSigner([]*jwt.PrivateKey{ks.PrivKey})
	if err != nil {
		t.Fatalf("NewSigner: %v", err)
	}
	tokenStr, err := signer.SignToString(testkeys.TestClaims(sub))
	if err != nil {
		t.Fatalf("SignToString: %v", err)
	}

	// Verify at JWS level.
	_, err = jws.Verify([]byte(tokenStr), jws.WithKey(jwxAlg(ks.AlgName), ks.RawPub))
	if err != nil {
		t.Fatalf("jwx jws.Verify: %v", err)
	}

	// Verify at JWT level and check claims.
	tok, err := jwxjwt.Parse([]byte(tokenStr), jwxjwt.WithKey(jwxAlg(ks.AlgName), ks.RawPub))
	if err != nil {
		t.Fatalf("jwx jwt.Parse: %v", err)
	}
	gotSub, ok := tok.Subject()
	if !ok || gotSub != sub {
		t.Errorf("sub: got %q (ok=%v), want %q", gotSub, ok, sub)
	}
	gotIss, ok := tok.Issuer()
	if !ok || gotIss != "https://example.com" {
		t.Errorf("iss: got %q (ok=%v), want %q", gotIss, ok, "https://example.com")
	}
}

func assertJWXSignOurVerify(t *testing.T, ks testkeys.KeySet, sub string) {
	t.Helper()

	// Import raw key into jwx and set kid.
	jwxKey, err := jwxjwk.Import(ks.RawPriv)
	if err != nil {
		t.Fatalf("jwk.Import: %v", err)
	}
	if err := jwxKey.Set(jwxjwk.KeyIDKey, ks.KID); err != nil {
		t.Fatalf("set kid: %v", err)
	}

	tok := jwxjwt.New()
	tok.Set(jwxjwt.SubjectKey, sub)
	tok.Set(jwxjwt.IssuerKey, "https://example.com")
	tok.Set(jwxjwt.ExpirationKey, time.Now().Add(time.Hour))
	tok.Set(jwxjwt.IssuedAtKey, time.Now())

	signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwxAlg(ks.AlgName), jwxKey))
	if err != nil {
		t.Fatalf("jwx jwt.Sign: %v", err)
	}

	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	verifiedJWS, err := verifier.VerifyJWT(string(signed))
	if err != nil {
		t.Fatalf("our verify: %v", err)
	}

	var decoded jwt.TokenClaims
	if err := verifiedJWS.UnmarshalClaims(&decoded); err != nil {
		t.Fatalf("UnmarshalClaims: %v", err)
	}
	if decoded.Sub != sub {
		t.Errorf("sub: got %q, want %q", decoded.Sub, sub)
	}
}

// --- Our sign, jwx verify (all algorithms) ---

func TestOurSignJWXVerify_EdDSA(t *testing.T) {
	assertOurSignJWXVerify(t, testkeys.GenerateEdDSA("k1"), "user-eddsa")
}

func TestOurSignJWXVerify_ES256(t *testing.T) {
	assertOurSignJWXVerify(t, testkeys.GenerateES256("k1"), "user-es256")
}

func TestOurSignJWXVerify_ES384(t *testing.T) {
	assertOurSignJWXVerify(t, testkeys.GenerateES384("k1"), "user-es384")
}

func TestOurSignJWXVerify_ES512(t *testing.T) {
	assertOurSignJWXVerify(t, testkeys.GenerateES512("k1"), "user-es512")
}

func TestOurSignJWXVerify_RS256(t *testing.T) {
	assertOurSignJWXVerify(t, testkeys.GenerateRS256("k1"), "user-rs256")
}

// --- jwx sign, our verify (all algorithms) ---

func TestJWXSignOurVerify_EdDSA(t *testing.T) {
	assertJWXSignOurVerify(t, testkeys.GenerateEdDSA("k1"), "user-eddsa")
}

func TestJWXSignOurVerify_ES256(t *testing.T) {
	assertJWXSignOurVerify(t, testkeys.GenerateES256("k1"), "user-es256")
}

func TestJWXSignOurVerify_ES384(t *testing.T) {
	assertJWXSignOurVerify(t, testkeys.GenerateES384("k1"), "user-es384")
}

func TestJWXSignOurVerify_ES512(t *testing.T) {
	assertJWXSignOurVerify(t, testkeys.GenerateES512("k1"), "user-es512")
}

func TestJWXSignOurVerify_RS256(t *testing.T) {
	assertJWXSignOurVerify(t, testkeys.GenerateRS256("k1"), "user-rs256")
}

// --- JWK serialization interop ---

func TestJWKInterop_OurJSONToJWX(t *testing.T) {
	for _, ag := range testkeys.AllAlgorithms() {
		t.Run(ag.Name+"_Public", func(t *testing.T) {
			ks := ag.Generate("jwk-" + ag.Name)

			// Marshal our public key to JSON.
			ourJSON, err := json.Marshal(ks.PubKey)
			if err != nil {
				t.Fatalf("marshal our pubkey: %v", err)
			}

			// Parse with jwx.
			jwxKey, err := jwxjwk.ParseKey(ourJSON)
			if err != nil {
				t.Fatalf("jwx ParseKey from our JSON: %v", err)
			}

			// Verify a token signed by us, using the jwx-parsed key.
			signer, err := jwt.NewSigner([]*jwt.PrivateKey{ks.PrivKey})
			if err != nil {
				t.Fatal(err)
			}
			tokenStr, err := signer.SignToString(testkeys.TestClaims("jwk-interop"))
			if err != nil {
				t.Fatal(err)
			}

			// Export the raw public key from the jwx Key.
			var rawPub any
			if err := jwxjwk.Export(jwxKey, &rawPub); err != nil {
				t.Fatalf("jwx Export: %v", err)
			}
			_, err = jws.Verify([]byte(tokenStr), jws.WithKey(jwxAlg(ks.AlgName), rawPub))
			if err != nil {
				t.Fatalf("jwx verify with our-JSON-parsed key: %v", err)
			}
		})

		t.Run(ag.Name+"_Private", func(t *testing.T) {
			ks := ag.Generate("jwk-priv-" + ag.Name)

			// Marshal our private key to JSON.
			ourJSON, err := json.Marshal(ks.PrivKey)
			if err != nil {
				t.Fatalf("marshal our privkey: %v", err)
			}

			// Parse with jwx.
			jwxKey, err := jwxjwk.ParseKey(ourJSON)
			if err != nil {
				t.Fatalf("jwx ParseKey from our private JSON: %v", err)
			}

			// Sign with the jwx-parsed key, verify with our lib.
			if err := jwxKey.Set(jwxjwk.KeyIDKey, ks.KID); err != nil {
				t.Fatal(err)
			}
			tok := jwxjwt.New()
			tok.Set(jwxjwt.SubjectKey, "jwk-priv-interop")
			tok.Set(jwxjwt.ExpirationKey, time.Now().Add(time.Hour))
			signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwxAlg(ks.AlgName), jwxKey))
			if err != nil {
				t.Fatalf("jwx sign with our-JSON-parsed key: %v", err)
			}

			verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
			if _, err := verifier.VerifyJWT(string(signed)); err != nil {
				t.Fatalf("our verify: %v", err)
			}
		})
	}
}

func TestJWKInterop_JWXJSONToOur(t *testing.T) {
	for _, ag := range testkeys.AllAlgorithms() {
		t.Run(ag.Name, func(t *testing.T) {
			ks := ag.Generate("jwx-to-our-" + ag.Name)

			// Create jwx key and serialize.
			jwxKey, err := jwxjwk.Import(ks.RawPub)
			if err != nil {
				t.Fatal(err)
			}
			jwxKey.Set(jwxjwk.KeyIDKey, ks.KID)
			jwxJSON, err := json.Marshal(jwxKey)
			if err != nil {
				t.Fatalf("marshal jwx key: %v", err)
			}

			// Parse with our library.
			var recovered jwt.PublicKey
			if err := json.Unmarshal(jwxJSON, &recovered); err != nil {
				t.Fatalf("our unmarshal of jwx JSON: %v", err)
			}

			// Sign with our signer, verify with the recovered key.
			signer, err := jwt.NewSigner([]*jwt.PrivateKey{ks.PrivKey})
			if err != nil {
				t.Fatal(err)
			}
			tokenStr, err := signer.SignToString(testkeys.TestClaims("jwx-json"))
			if err != nil {
				t.Fatal(err)
			}
			verifier, _ := jwt.NewVerifier([]jwt.PublicKey{recovered})
			if _, err := verifier.VerifyJWT(tokenStr); err != nil {
				t.Fatalf("verify with jwx-JSON-parsed key: %v", err)
			}
		})
	}
}

// --- Thumbprint consistency (RFC 7638) ---

func TestThumbprintConsistency_JWX(t *testing.T) {
	for _, ag := range testkeys.AllAlgorithms() {
		t.Run(ag.Name, func(t *testing.T) {
			ks := ag.Generate("thumb-" + ag.Name)

			// Our thumbprint (returns base64url string).
			ourThumb, err := ks.PubKey.Thumbprint()
			if err != nil {
				t.Fatalf("our Thumbprint: %v", err)
			}

			// jwx thumbprint (returns raw bytes).
			jwxKey, err := jwxjwk.Import(ks.RawPub)
			if err != nil {
				t.Fatal(err)
			}
			jwxRaw, err := jwxKey.Thumbprint(crypto.SHA256)
			if err != nil {
				t.Fatalf("jwx Thumbprint: %v", err)
			}
			jwxThumb := base64.RawURLEncoding.EncodeToString(jwxRaw)

			if ourThumb != jwxThumb {
				t.Errorf("thumbprint mismatch:\n  ours: %s\n  jwx:  %s", ourThumb, jwxThumb)
			}
		})
	}
}

// --- JWKS interop ---

func TestJWKSInterop_OurToJWX(t *testing.T) {
	// Build a signer with all 5 key types.
	var keys []*jwt.PrivateKey
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

	// Parse with jwx.
	jwxSet, err := jwxjwk.Parse(jwksData)
	if err != nil {
		t.Fatalf("jwx Parse JWKS: %v", err)
	}
	if jwxSet.Len() != 5 {
		t.Fatalf("expected 5 keys, got %d", jwxSet.Len())
	}

	// Sign tokens with each key and verify with the jwx-parsed set.
	for i, ks := range sets {
		tokenStr, err := signer.SignToString(testkeys.TestClaims(fmt.Sprintf("jwks-%d", i)))
		if err != nil {
			t.Fatalf("sign[%d]: %v", i, err)
		}
		_, err = jws.Verify([]byte(tokenStr), jws.WithKeySet(jwxSet))
		if err != nil {
			t.Errorf("jwx verify[%d] (%s) with parsed JWKS: %v", i, ks.AlgName, err)
		}
	}
}

func TestJWKSInterop_JWXToOur(t *testing.T) {
	// Build a jwx key set.
	jwxSet := jwxjwk.NewSet()
	var sets []testkeys.KeySet
	for _, ag := range testkeys.AllAlgorithms() {
		ks := ag.Generate("jwx-jwks-" + ag.Name)
		sets = append(sets, ks)
		jwxKey, err := jwxjwk.Import(ks.RawPub)
		if err != nil {
			t.Fatal(err)
		}
		jwxKey.Set(jwxjwk.KeyIDKey, ks.KID)
		jwxKey.Set(jwxjwk.AlgorithmKey, jwxAlg(ks.AlgName))
		if err := jwxSet.AddKey(jwxKey); err != nil {
			t.Fatal(err)
		}
	}

	// Serialize jwx JWKS.
	jwksData, err := json.Marshal(jwxSet)
	if err != nil {
		t.Fatal(err)
	}

	// Parse with our library.
	var ourJWKS jwt.WellKnownJWKs
	if err := json.Unmarshal(jwksData, &ourJWKS); err != nil {
		t.Fatalf("our unmarshal of jwx JWKS: %v", err)
	}
	if len(ourJWKS.Keys) != 5 {
		t.Fatalf("expected 5 keys, got %d", len(ourJWKS.Keys))
	}

	verifier, _ := jwt.NewVerifier(ourJWKS.Keys)

	// Sign tokens with jwx, verify with our library.
	for _, ks := range sets {
		jwxKey, _ := jwxjwk.Import(ks.RawPriv)
		jwxKey.Set(jwxjwk.KeyIDKey, ks.KID)
		tok := jwxjwt.New()
		tok.Set(jwxjwt.SubjectKey, "jwx-to-our")
		tok.Set(jwxjwt.ExpirationKey, time.Now().Add(time.Hour))
		signed, err := jwxjwt.Sign(tok, jwxjwt.WithKey(jwxAlg(ks.AlgName), jwxKey))
		if err != nil {
			t.Fatalf("jwx sign %s: %v", ks.AlgName, err)
		}
		if _, err := verifier.VerifyJWT(string(signed)); err != nil {
			t.Errorf("our verify %s from jwx JWKS: %v", ks.AlgName, err)
		}
	}
}

// --- Audience interop ---

func TestAudienceStringInterop_JWX(t *testing.T) {
	ks := testkeys.GenerateEdDSA("aud-test")

	// Our library: single aud marshals as plain string "single-aud".
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{ks.PrivKey})
	if err != nil {
		t.Fatal(err)
	}
	claims := testkeys.ListishClaims("aud-str", jwt.Listish{"single-aud"})
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := jwxjwt.Parse([]byte(tokenStr), jwxjwt.WithKey(jwa.EdDSA(), ks.RawPub))
	if err != nil {
		t.Fatalf("jwx parse: %v", err)
	}
	aud, ok := tok.Audience()
	if !ok || len(aud) != 1 || aud[0] != "single-aud" {
		t.Errorf("aud: got %v (ok=%v), want [single-aud]", aud, ok)
	}

	// Reverse: jwx signs with single aud, our library parses.
	jwxKey, _ := jwxjwk.Import(ks.RawPriv)
	jwxKey.Set(jwxjwk.KeyIDKey, ks.KID)
	jwxTok := jwxjwt.New()
	jwxTok.Set(jwxjwt.ListishKey, []string{"single-aud"})
	jwxTok.Set(jwxjwt.SubjectKey, "aud-str-rev")
	jwxTok.Set(jwxjwt.ExpirationKey, time.Now().Add(time.Hour))
	signed, err := jwxjwt.Sign(jwxTok, jwxjwt.WithKey(jwa.EdDSA(), jwxKey))
	if err != nil {
		t.Fatal(err)
	}
	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	verifiedJWS, err := verifier.VerifyJWT(string(signed))
	if err != nil {
		t.Fatal(err)
	}
	var decoded jwt.TokenClaims
	verifiedJWS.UnmarshalClaims(&decoded)
	if len(decoded.Aud) == 0 || decoded.Aud[0] != "single-aud" {
		t.Errorf("reverse aud: got %v, want [single-aud]", decoded.Aud)
	}
}

func TestAudienceArrayInterop_JWX(t *testing.T) {
	ks := testkeys.GenerateEdDSA("aud-arr")

	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{ks.PrivKey})
	claims := testkeys.ListishClaims("aud-arr", jwt.Listish{"aud1", "aud2"})
	tokenStr, _ := signer.SignToString(claims)

	tok, err := jwxjwt.Parse([]byte(tokenStr), jwxjwt.WithKey(jwa.EdDSA(), ks.RawPub))
	if err != nil {
		t.Fatalf("jwx parse: %v", err)
	}
	aud, _ := tok.Audience()
	if len(aud) != 2 || aud[0] != "aud1" || aud[1] != "aud2" {
		t.Errorf("aud: got %v, want [aud1 aud2]", aud)
	}
}

// --- Custom claims interop ---

func TestCustomClaimsInterop_JWX(t *testing.T) {
	ks := testkeys.GenerateEdDSA("custom")
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{ks.PrivKey})
	claims := &testkeys.CustomClaims{
		TokenClaims: *testkeys.TestClaims("custom-user"),
		Email:         "user@example.com",
		Roles:         []string{"admin", "editor"},
		Metadata:      map[string]string{"team": "platform"},
	}
	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}

	tok, err := jwxjwt.Parse([]byte(tokenStr), jwxjwt.WithKey(jwa.EdDSA(), ks.RawPub))
	if err != nil {
		t.Fatalf("jwx parse: %v", err)
	}

	var email string
	if err := tok.Get("email", &email); err != nil {
		t.Fatalf("get email: %v", err)
	}
	if email != "user@example.com" {
		t.Errorf("email: got %q, want %q", email, "user@example.com")
	}

	var roles []any
	if err := tok.Get("roles", &roles); err != nil {
		t.Fatalf("get roles: %v", err)
	}
	if len(roles) != 2 || fmt.Sprint(roles[0]) != "admin" {
		t.Errorf("roles: got %v, want [admin editor]", roles)
	}

	var meta map[string]any
	if err := tok.Get("metadata", &meta); err != nil {
		t.Fatalf("get metadata: %v", err)
	}
	if meta["team"] != "platform" {
		t.Errorf("metadata.team: got %v, want %q", meta["team"], "platform")
	}
}

// --- NumericDate precision ---

func TestNumericDatePrecision_JWX(t *testing.T) {
	ks := testkeys.GenerateEdDSA("nd")

	// Use fixed future timestamps to test precision without triggering
	// expiration validation. 2000000000 = 2033-05-18, well in the future.
	var wantExp int64 = 2000000000
	var wantIat int64 = 1999999000
	claims := &jwt.TokenClaims{
		Iss: "https://example.com",
		Sub: "numdate",
		Exp: wantExp,
		IAt: wantIat,
	}
	signer, _ := jwt.NewSigner([]*jwt.PrivateKey{ks.PrivKey})
	tokenStr, _ := signer.SignToString(claims)

	// Disable validation - this test is about timestamp precision, not
	// expiration checking. jwx rejects future iat by default.
	tok, err := jwxjwt.Parse([]byte(tokenStr),
		jwxjwt.WithKey(jwa.EdDSA(), ks.RawPub),
		jwxjwt.WithValidate(false),
	)
	if err != nil {
		t.Fatal(err)
	}
	exp, ok := tok.Expiration()
	if !ok || exp.Unix() != wantExp {
		t.Errorf("exp: got %d (ok=%v), want %d", exp.Unix(), ok, wantExp)
	}
	iat, ok := tok.IssuedAt()
	if !ok || iat.Unix() != wantIat {
		t.Errorf("iat: got %d (ok=%v), want %d", iat.Unix(), ok, wantIat)
	}

	// Reverse: jwx signs with specific times, our library reads.
	var wantExp2 int64 = 2100000000
	var wantIat2 int64 = 2099999000
	jwxKey, _ := jwxjwk.Import(ks.RawPriv)
	jwxKey.Set(jwxjwk.KeyIDKey, ks.KID)
	jwxTok := jwxjwt.New()
	jwxTok.Set(jwxjwt.SubjectKey, "numdate-rev")
	jwxTok.Set(jwxjwt.ExpirationKey, time.Unix(wantExp2, 0))
	jwxTok.Set(jwxjwt.IssuedAtKey, time.Unix(wantIat2, 0))
	signed, _ := jwxjwt.Sign(jwxTok, jwxjwt.WithKey(jwa.EdDSA(), jwxKey))

	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	verifiedJWS, _ := verifier.VerifyJWT(string(signed))
	var decoded jwt.TokenClaims
	verifiedJWS.UnmarshalClaims(&decoded)
	if decoded.Exp != wantExp2 {
		t.Errorf("rev exp: got %d, want %d", decoded.Exp, wantExp2)
	}
	if decoded.IAt != wantIat2 {
		t.Errorf("rev iat: got %d, want %d", decoded.IAt, wantIat2)
	}
}

// --- Stress tests ---

func TestStress_JWX(t *testing.T) {
	for _, ag := range testkeys.AllAlgorithms() {
		ag := ag
		t.Run(ag.Name, func(t *testing.T) {
			t.Parallel()
			n := 1000
			if ag.Name == "RS256" {
				n = 10
				if *longTests {
					n = 100
				}
			}
			for i := range n {
				ks := ag.Generate(fmt.Sprintf("s%d", i))
				sub := fmt.Sprintf("stress-%d", i)

				// Our sign, jwx verify.
				signer, err := jwt.NewSigner([]*jwt.PrivateKey{ks.PrivKey})
				if err != nil {
					t.Fatalf("iter %d: NewSigner: %v", i, err)
				}
				tokenStr, err := signer.SignToString(testkeys.TestClaims(sub))
				if err != nil {
					t.Fatalf("iter %d: SignToString: %v", i, err)
				}
				_, err = jws.Verify([]byte(tokenStr), jws.WithKey(jwxAlg(ks.AlgName), ks.RawPub))
				if err != nil {
					t.Fatalf("iter %d: jwx verify: %v", i, err)
				}

				// jwx sign, our verify.
				jwxKey, _ := jwxjwk.Import(ks.RawPriv)
				jwxKey.Set(jwxjwk.KeyIDKey, ks.KID)
				jwxTok := jwxjwt.New()
				jwxTok.Set(jwxjwt.SubjectKey, sub)
				jwxTok.Set(jwxjwt.ExpirationKey, time.Now().Add(time.Hour))
				signed, err := jwxjwt.Sign(jwxTok, jwxjwt.WithKey(jwxAlg(ks.AlgName), jwxKey))
				if err != nil {
					t.Fatalf("iter %d: jwx sign: %v", i, err)
				}
				verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
				if _, err := verifier.VerifyJWT(string(signed)); err != nil {
					t.Fatalf("iter %d: our verify: %v", i, err)
				}
			}
		})
	}
}
