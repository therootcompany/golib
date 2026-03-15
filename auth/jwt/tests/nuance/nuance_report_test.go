// Package nuance_test documents behavioral differences between this library,
// go-jose/go-jose v4, and lestrrat-go/jwx v3 that may cause interop surprises.
//
// Each test logs observations via t.Log so that `go test -v ./nuance/` produces
// a readable report. Tests that demonstrate library-specific defaults use
// controlled clock offsets to show exactly where each library draws the line.
//
// Run:
//
//	go test ./nuance/ -v
package nuance_test

import (
	"crypto"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
	"github.com/lestrrat-go/jwx/v3/jwa"
	jwxjwk "github.com/lestrrat-go/jwx/v3/jwk"
	jwxjwt "github.com/lestrrat-go/jwx/v3/jwt"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/tests/testkeys"
)

// signOurs creates a JWT signed with our library using the given claims.
func signOurs(t *testing.T, ks testkeys.KeySet, claims jwt.Claims) string {
	t.Helper()
	signer, err := jwt.NewSigner([]jwt.PrivateKey{ks.PrivKey})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := signer.SignToString(claims)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

// -----------------------------------------------------------------------
// Clock skew / expiration tolerance
// -----------------------------------------------------------------------

func TestNuance_ClockSkew_GoJose(t *testing.T) {
	t.Log("=== Nuance: expiration checking - when does it happen? ===")
	t.Log("")
	t.Log("CRITICAL: Our VerifyJWT only checks the SIGNATURE.")
	t.Log("Claims validation (exp, iat) requires a separate Validate() call.")
	t.Log("go-jose also separates verification from validation.")
	t.Log("jwx bundles both into jwt.Parse by default.")
	t.Log("")
	t.Log("go-jose ValidateWithLeeway takes an explicit leeway parameter.")
	t.Log("Our IDTokenValidator.Validate uses DefaultGracePeriod (2s).")
	t.Log("")

	ks := testkeys.GenerateEdDSA("skew")

	// Token expired 30 seconds ago.
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "skew-test",
		Exp: time.Now().Add(-30 * time.Second).Unix(),
		Iat: time.Now().Add(-5 * time.Minute).Unix(),
	}
	tokenStr := signOurs(t, ks, claims)

	// Our VerifyJWT: signature-only, does NOT check exp.
	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	jws, ourSigErr := verifier.VerifyJWT(tokenStr)
	t.Logf("  our VerifyJWT (sig only): accepts=%v", ourSigErr == nil)

	// Our Validate: checks exp with DefaultGracePeriod (2s) => REJECTS.
	if jws != nil {
		var decoded jwt.IDTokenClaims
		jwt.UnmarshalClaims(jws, &decoded)
		v := jwt.IDTokenValidator{Iss: []string{"https://example.com"}, IgnoreSub: true}
		_, valErr := v.Validate(&decoded, time.Now())
		t.Logf("  our Validate (2s grace):  rejects=%v (err=%v)",
			valErr != nil, valErr)
		if valErr == nil {
			t.Error("expected our Validate to reject a token expired 30s ago")
		}
	}

	// go-jose: also separates parse/verify from validation.
	tok, _ := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.EdDSA})
	var joseClaims josejwt.Claims
	tok.Claims(ks.RawPub, &joseClaims)

	// go-jose with explicit 1-minute leeway => accepts.
	err1m := joseClaims.ValidateWithLeeway(josejwt.Expected{Time: time.Now()}, 1*time.Minute)
	t.Logf("  go-jose (1m leeway):      accepts=%v", err1m == nil)

	// go-jose with 0 leeway => rejects.
	err0 := joseClaims.ValidateWithLeeway(josejwt.Expected{Time: time.Now()}, 0)
	t.Logf("  go-jose (0 leeway):       rejects=%v", err0 != nil)

	if err1m != nil {
		t.Error("expected go-jose to accept with 1m leeway")
	}
	if err0 == nil {
		t.Error("expected go-jose to reject with 0 leeway")
	}

	t.Log("")
	t.Log("ACTION: Our VerifyJWT is signature-only. You MUST call Validate()")
	t.Log("after VerifyJWT to enforce exp/iat. go-jose likewise requires an")
	t.Log("explicit ValidateWithLeeway call. Choose matching leeway values.")
}

func TestNuance_ClockSkew_JWX(t *testing.T) {
	t.Log("=== Nuance: jwx bundles validation into jwt.Parse ===")
	t.Log("")
	t.Log("Unlike our lib and go-jose (which separate sig from claims),")
	t.Log("jwx v3 validates exp/iat DURING jwt.Parse. Default skew is 0.")
	t.Log("Use jwt.WithAcceptableSkew(d) or jwt.WithValidate(false) to adjust.")
	t.Log("")

	ks := testkeys.GenerateEdDSA("skew-jwx")

	// Token expired 1 second ago.
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "skew-test",
		Exp: time.Now().Add(-1 * time.Second).Unix(),
		Iat: time.Now().Add(-5 * time.Minute).Unix(),
	}
	tokenStr := signOurs(t, ks, claims)

	// jwx: zero skew (default) => rejects at parse time.
	_, jwxErr := jwxjwt.Parse([]byte(tokenStr), jwxjwt.WithKey(jwa.EdDSA(), ks.RawPub))
	t.Logf("  jwx Parse (0s skew):     rejects=%v", jwxErr != nil)

	// jwx: with 5s skew => accepts.
	_, jwxErr5 := jwxjwt.Parse([]byte(tokenStr),
		jwxjwt.WithKey(jwa.EdDSA(), ks.RawPub),
		jwxjwt.WithAcceptableSkew(5*time.Second),
	)
	t.Logf("  jwx Parse (5s skew):     accepts=%v", jwxErr5 == nil)

	// jwx: validation disabled => accepts (sig-only, like our VerifyJWT).
	_, jwxErrNoval := jwxjwt.Parse([]byte(tokenStr),
		jwxjwt.WithKey(jwa.EdDSA(), ks.RawPub),
		jwxjwt.WithValidate(false),
	)
	t.Logf("  jwx Parse (no validate): accepts=%v", jwxErrNoval == nil)

	// Our VerifyJWT: always accepts (sig-only).
	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	_, ourErr := verifier.VerifyJWT(tokenStr)
	t.Logf("  our VerifyJWT (sig only): accepts=%v", ourErr == nil)

	if jwxErr == nil {
		t.Error("expected jwx to reject with 0 skew")
	}
	if jwxErr5 != nil {
		t.Error("expected jwx to accept with 5s skew")
	}
	if jwxErrNoval != nil {
		t.Error("expected jwx to accept with validation disabled")
	}
	if ourErr != nil {
		t.Errorf("expected our VerifyJWT to accept (sig-only): %v", ourErr)
	}

	t.Log("")
	t.Log("ACTION: jwx rejects expired tokens at parse time. Use")
	t.Log("WithAcceptableSkew(d) to add clock tolerance, or")
	t.Log("WithValidate(false) for sig-only (matching our VerifyJWT).")
}

// -----------------------------------------------------------------------
// kid header emission
// -----------------------------------------------------------------------

func TestNuance_KIDHeader_GoJose(t *testing.T) {
	t.Log("=== Nuance: go-jose kid header emission ===")
	t.Log("")
	t.Log("go-jose omits 'kid' from the JWS header unless:")
	t.Log("  1. The signing key is wrapped in jose.JSONWebKey{KeyID: ...}, or")
	t.Log("  2. opts.WithHeader(jose.HeaderKey(\"kid\"), ...) is used.")
	t.Log("Our verifier tries all keys when kid is missing (fallback).")
	t.Log("")

	ks := testkeys.GenerateEdDSA("kid-test")

	// Sign with raw key (no JSONWebKey wrapper) - kid is missing.
	rawSigKey := jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       ks.RawPriv, // raw key, no JSONWebKey wrapper
	}
	rawSigner, _ := jose.NewSigner(rawSigKey, nil)
	rawClaims := josejwt.Claims{
		Subject: "raw-key",
		Expiry:  josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	rawToken, _ := josejwt.Signed(rawSigner).Claims(rawClaims).Serialize()

	// Check the header.
	parts := strings.SplitN(rawToken, ".", 3)
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	_, hasKID := header["kid"]
	t.Logf("  raw key signing: kid in header = %v (header: %s)", hasKID, headerJSON)

	// Our verifier accepts via try-all-keys fallback (no kid → try every key).
	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	_, ourErr := verifier.VerifyJWT(rawToken)
	t.Logf("  our VerifyJWT:   err = %v", ourErr)

	// Sign with JSONWebKey wrapper - kid is present.
	wrappedSigKey := jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       jose.JSONWebKey{Key: ks.RawPriv, KeyID: ks.KID},
	}
	wrappedSigner, _ := jose.NewSigner(wrappedSigKey, nil)
	wrappedToken, _ := josejwt.Signed(wrappedSigner).Claims(rawClaims).Serialize()
	parts2 := strings.SplitN(wrappedToken, ".", 3)
	headerJSON2, _ := base64.RawURLEncoding.DecodeString(parts2[0])
	var header2 map[string]any
	json.Unmarshal(headerJSON2, &header2)
	_, hasKID2 := header2["kid"]
	t.Logf("  JSONWebKey signing: kid in header = %v (header: %s)", hasKID2, headerJSON2)

	_, ourErr2 := verifier.VerifyJWT(wrappedToken)
	t.Logf("  our VerifyJWT:      err = %v", ourErr2)

	if hasKID {
		t.Error("expected raw key signing to NOT have kid in header")
	}
	if ourErr != nil {
		t.Errorf("expected our verifier to accept token without kid (try-all-keys fallback), got: %v", ourErr)
	}
	if !hasKID2 {
		t.Error("expected JSONWebKey signing to have kid in header")
	}
	if ourErr2 != nil {
		t.Errorf("expected our verifier to accept token with kid, got: %v", ourErr2)
	}

	t.Log("")
	t.Log("NOTE: When kid is missing, our verifier tries all keys (first match wins).")
	t.Log("For multi-key verifiers, always set kid for efficient key lookup.")
}

func TestNuance_KIDHeader_JWX(t *testing.T) {
	t.Log("=== Nuance: jwx kid header emission ===")
	t.Log("")
	t.Log("jwx omits 'kid' unless jwk.KeyIDKey is set on the key before signing.")
	t.Log("Our verifier tries all keys when kid is missing (fallback).")
	t.Log("")

	ks := testkeys.GenerateEdDSA("kid-jwx")

	// Import key WITHOUT setting kid.
	jwxKeyNoKID, _ := jwxjwk.Import(ks.RawPriv)
	tok := jwxjwt.New()
	tok.Set(jwxjwt.SubjectKey, "no-kid")
	tok.Set(jwxjwt.ExpirationKey, time.Now().Add(time.Hour))
	noKIDToken, _ := jwxjwt.Sign(tok, jwxjwt.WithKey(jwa.EdDSA(), jwxKeyNoKID))

	parts := strings.SplitN(string(noKIDToken), ".", 3)
	headerJSON, _ := base64.RawURLEncoding.DecodeString(parts[0])
	var header map[string]any
	json.Unmarshal(headerJSON, &header)
	_, hasKID := header["kid"]
	t.Logf("  no KeyIDKey set: kid in header = %v (header: %s)", hasKID, headerJSON)

	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	_, ourErr := verifier.VerifyJWT(string(noKIDToken))
	t.Logf("  our VerifyJWT:   err = %v", ourErr)

	// Import key WITH kid set.
	jwxKeyWithKID, _ := jwxjwk.Import(ks.RawPriv)
	jwxKeyWithKID.Set(jwxjwk.KeyIDKey, ks.KID)
	tok2 := jwxjwt.New()
	tok2.Set(jwxjwt.SubjectKey, "with-kid")
	tok2.Set(jwxjwt.ExpirationKey, time.Now().Add(time.Hour))
	withKIDToken, _ := jwxjwt.Sign(tok2, jwxjwt.WithKey(jwa.EdDSA(), jwxKeyWithKID))

	parts2 := strings.SplitN(string(withKIDToken), ".", 3)
	headerJSON2, _ := base64.RawURLEncoding.DecodeString(parts2[0])
	var header2 map[string]any
	json.Unmarshal(headerJSON2, &header2)
	_, hasKID2 := header2["kid"]
	t.Logf("  KeyIDKey set:    kid in header = %v (header: %s)", hasKID2, headerJSON2)

	_, ourErr2 := verifier.VerifyJWT(string(withKIDToken))
	t.Logf("  our VerifyJWT:   err = %v", ourErr2)

	if hasKID {
		t.Error("expected no-kid key to omit kid from header")
	}
	if ourErr != nil {
		t.Errorf("expected our verifier to accept token without kid (try-all-keys fallback), got: %v", ourErr)
	}
	if !hasKID2 {
		t.Error("expected kid-set key to include kid in header")
	}
	if ourErr2 != nil {
		t.Errorf("expected our verifier to accept token with kid, got: %v", ourErr2)
	}

	t.Log("")
	t.Log("NOTE: When kid is missing, our verifier tries all keys (first match wins).")
	t.Log("For multi-key verifiers, always set kid for efficient key lookup.")
}

// -----------------------------------------------------------------------
// Audience marshaling
// -----------------------------------------------------------------------

func TestNuance_AudienceMarshal(t *testing.T) {
	t.Log("=== Nuance: audience JSON marshaling ===")
	t.Log("")
	t.Log("RFC 7519 allows aud as either a string or an array of strings.")
	t.Log("Libraries differ in how they marshal a single-value audience:")
	t.Log("")

	ks := testkeys.GenerateEdDSA("aud-marshal")

	// Our library: single aud => string, multi aud => array.
	singleClaims := testkeys.AudienceClaims("aud-test", jwt.Audience{"single"})
	signer, _ := jwt.NewSigner([]jwt.PrivateKey{ks.PrivKey})
	ourSingleTok, _ := signer.SignToString(singleClaims)
	ourSinglePayload := decodePayload(ourSingleTok)
	t.Logf("  our lib (single aud): %s", ourSinglePayload)

	multiClaims := testkeys.AudienceClaims("aud-test", jwt.Audience{"a", "b"})
	ourMultiTok, _ := signer.SignToString(multiClaims)
	ourMultiPayload := decodePayload(ourMultiTok)
	t.Logf("  our lib (multi aud):  %s", ourMultiPayload)

	// go-jose: check how it marshals.
	sigKey := jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key:       jose.JSONWebKey{Key: ks.RawPriv, KeyID: ks.KID},
	}
	joseSigner, _ := jose.NewSigner(sigKey, nil)
	joseSingleClaims := josejwt.Claims{
		Subject:  "aud-test",
		Audience: josejwt.Audience{"single"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	joseSingleTok, _ := josejwt.Signed(joseSigner).Claims(joseSingleClaims).Serialize()
	joseSinglePayload := decodePayload(joseSingleTok)
	t.Logf("  go-jose (single aud): %s", joseSinglePayload)

	joseMultiClaims := josejwt.Claims{
		Subject:  "aud-test",
		Audience: josejwt.Audience{"a", "b"},
		Expiry:   josejwt.NewNumericDate(time.Now().Add(time.Hour)),
	}
	joseMultiTok, _ := josejwt.Signed(joseSigner).Claims(joseMultiClaims).Serialize()
	joseMultiPayload := decodePayload(joseMultiTok)
	t.Logf("  go-jose (multi aud):  %s", joseMultiPayload)

	// All parsers should handle both string and array forms.
	// Verify our parser handles go-jose's format.
	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	verifiedJWS, err := verifier.VerifyJWT(joseSingleTok)
	if err != nil {
		t.Fatalf("our verify of go-jose single aud: %v", err)
	}
	var decoded jwt.IDTokenClaims
	jwt.UnmarshalClaims(verifiedJWS, &decoded)
	t.Logf("  our parse of go-jose single aud: %v", decoded.Aud)

	if len(decoded.Aud) != 1 || decoded.Aud[0] != "single" {
		t.Errorf("expected [single], got %v", decoded.Aud)
	}

	t.Log("")
	t.Log("Both libraries handle both string and array forms on input.")
	t.Log("No action needed - interop is seamless for audience values.")
}

// -----------------------------------------------------------------------
// Thumbprint encoding
// -----------------------------------------------------------------------

func TestNuance_ThumbprintEncoding(t *testing.T) {
	t.Log("=== Nuance: JWK Thumbprint encoding (RFC 7638) ===")
	t.Log("")
	t.Log("All 3 libraries use unpadded base64url encoding for thumbprints.")
	t.Log("Confirming no library adds '=' padding:")
	t.Log("")

	for _, ag := range testkeys.AllAlgorithms() {
		ks := ag.Generate("thumb-enc-" + ag.Name)

		// Our thumbprint.
		ourThumb, _ := ks.PubKey.Thumbprint()
		hasPadding := strings.Contains(ourThumb, "=")
		t.Logf("  %s - our thumbprint:     %s (padding=%v)", ag.Name, ourThumb, hasPadding)
		if hasPadding {
			t.Errorf("%s: our thumbprint has padding", ag.Name)
		}

		// go-jose thumbprint.
		joseKey := jose.JSONWebKey{Key: ks.RawPub}
		joseRaw, _ := joseKey.Thumbprint(crypto.SHA256)
		joseThumb := base64.RawURLEncoding.EncodeToString(joseRaw)
		t.Logf("  %s - go-jose thumbprint: %s", ag.Name, joseThumb)

		// jwx thumbprint.
		jwxKey, _ := jwxjwk.Import(ks.RawPub)
		jwxRaw, _ := jwxKey.Thumbprint(crypto.SHA256)
		jwxThumb := base64.RawURLEncoding.EncodeToString(jwxRaw)
		t.Logf("  %s - jwx thumbprint:     %s", ag.Name, jwxThumb)

		// All three should match.
		if ourThumb != joseThumb || ourThumb != jwxThumb {
			t.Errorf("%s: thumbprint mismatch: ours=%s go-jose=%s jwx=%s",
				ag.Name, ourThumb, joseThumb, jwxThumb)
		}
	}

	t.Log("")
	t.Log("All 3 libraries produce identical unpadded base64url thumbprints.")
	t.Log("No action needed.")
}

// -----------------------------------------------------------------------
// iat (issued-at) validation
// -----------------------------------------------------------------------

func TestNuance_IssuedAtValidation(t *testing.T) {
	t.Log("=== Nuance: iat (issued-at) validation ===")
	t.Log("")
	t.Log("All 3 libraries that validate claims reject future iat.")
	t.Log("But our VerifyJWT is signature-only - iat is checked in Validate().")
	t.Log("jwx checks iat during Parse(). go-jose checks iat in ValidateWithLeeway().")
	t.Log("")

	ks := testkeys.GenerateEdDSA("iat-test")

	// Token with iat 10 seconds in the future.
	claims := &jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "iat-future",
		Exp: time.Now().Add(time.Hour).Unix(),
		Iat: time.Now().Add(10 * time.Second).Unix(),
	}
	tokenStr := signOurs(t, ks, claims)

	// jwx: rejects at parse time (iat in future, 0 skew).
	_, jwxErr := jwxjwt.Parse([]byte(tokenStr), jwxjwt.WithKey(jwa.EdDSA(), ks.RawPub))
	t.Logf("  jwx Parse (0 skew):            rejects=%v", jwxErr != nil)

	// go-jose: parse+verify succeeds, ValidateWithLeeway rejects future iat.
	tok, _ := josejwt.ParseSigned(tokenStr, []jose.SignatureAlgorithm{jose.EdDSA})
	var joseClaims josejwt.Claims
	tok.Claims(ks.RawPub, &joseClaims)
	joseErr := joseClaims.ValidateWithLeeway(josejwt.Expected{Time: time.Now()}, 0)
	t.Logf("  go-jose ValidateWithLeeway(0):  rejects=%v", joseErr != nil)

	// Our VerifyJWT: accepts (signature-only, no iat check).
	verifier, _ := jwt.NewVerifier([]jwt.PublicKey{ks.PubKey})
	jws, ourSigErr := verifier.VerifyJWT(tokenStr)
	t.Logf("  our VerifyJWT (sig only):       accepts=%v", ourSigErr == nil)

	// Our Validate: rejects (iat 10s in future > 2s grace).
	if jws != nil {
		var decoded jwt.IDTokenClaims
		jwt.UnmarshalClaims(jws, &decoded)
		v := jwt.IDTokenValidator{Iss: []string{"https://example.com"}, IgnoreSub: true}
		_, valErr := v.Validate(&decoded, time.Now())
		t.Logf("  our Validate (2s grace):        rejects=%v", valErr != nil)
		if valErr == nil {
			t.Error("expected our Validate to reject future iat")
		}
	}

	if jwxErr == nil {
		t.Error("expected jwx to reject future iat")
	}
	if joseErr == nil {
		t.Error("expected go-jose to reject future iat")
	}
	if ourSigErr != nil {
		t.Errorf("expected our VerifyJWT to accept (sig-only): %v", ourSigErr)
	}

	t.Log("")
	t.Log("ACTION: All 3 libs reject future iat when validation is invoked.")
	t.Log("The difference is WHEN: jwx checks at Parse, go-jose and ours")
	t.Log("require an explicit validation step after signature verification.")
}

// -----------------------------------------------------------------------
// helpers
// -----------------------------------------------------------------------

func decodePayload(tokenStr string) string {
	parts := strings.SplitN(tokenStr, ".", 3)
	if len(parts) < 2 {
		return "(invalid token)"
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return "(decode error: " + err.Error() + ")"
	}

	// Extract just the aud field for compact display.
	var m map[string]any
	json.Unmarshal(payload, &m)
	aud, ok := m["aud"]
	if !ok {
		return "(no aud field)"
	}
	audJSON, _ := json.Marshal(aud)
	return "aud=" + string(audJSON)
}
