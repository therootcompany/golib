// Copyright 2026 AJ ONeal. SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"strings"
	"testing"
	"time"
)

// ============================================================
// Helpers
// ============================================================

var testNow = time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)

func mustECKey(t *testing.T, curve elliptic.Curve) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(curve, rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func mustEdKey(t *testing.T) ed25519.PrivateKey {
	t.Helper()
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return priv
}

func mustFromPrivate(t *testing.T, signer crypto.Signer) *PrivateKey {
	t.Helper()
	pk, err := FromPrivateKey(signer, "")
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

func mustSigner(t *testing.T, keys ...*PrivateKey) *Signer {
	t.Helper()
	s, err := NewSigner(keys)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func mustSignStr(t *testing.T, s *Signer, tc *TokenClaims) string {
	t.Helper()
	tok, err := s.SignToString(tc)
	if err != nil {
		t.Fatal(err)
	}
	return tok
}

func goodClaims() *TokenClaims {
	return &TokenClaims{
		Iss:      "https://example.com",
		Sub:      "user-123",
		Aud:      Listish{"https://api.example.com"},
		Exp:      testNow.Add(time.Hour).Unix(),
		IAt:      testNow.Add(-time.Minute).Unix(),
		JTI:      "jti-abc",
		AuthTime: testNow.Add(-5 * time.Minute).Unix(),
		AzP:      "client-abc",
		ClientID: "client-abc",
		Scope:    SpaceDelimited{"openid", "profile"},
	}
}

// fakeKey implements CryptoPublicKey but is not EC/RSA/Ed25519.
type fakeKey struct{}

func (fakeKey) Equal(crypto.PublicKey) bool { return false }

// fakeSigner is a crypto.Signer with fakeKey public key.
type fakeSigner struct{ pub crypto.PublicKey }

func (f fakeSigner) Public() crypto.PublicKey { return f.pub }
func (fakeSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, fmt.Errorf("not implemented")
}

// badClaims fails json.Marshal because of channel field.
type badClaims struct {
	TokenClaims
	Bad chan int `json:"bad"`
}

// ============================================================
// claims.go
// ============================================================

func TestCov_GetTokenClaims(t *testing.T) {
	tc := &TokenClaims{Iss: "x"}
	got := tc.GetTokenClaims()
	if got != tc {
		t.Fatal("expected same pointer")
	}
}

// ============================================================
// types.go - Listish
// ============================================================

func TestCov_Listish_UnmarshalJSON(t *testing.T) {
	t.Run("string", func(t *testing.T) {
		var l Listish
		if err := json.Unmarshal([]byte(`"https://ex.com"`), &l); err != nil {
			t.Fatal(err)
		}
		if len(l) != 1 || l[0] != "https://ex.com" {
			t.Fatalf("got %v", l)
		}
	})
	t.Run("empty_string", func(t *testing.T) {
		var l Listish
		if err := json.Unmarshal([]byte(`""`), &l); err != nil {
			t.Fatal(err)
		}
		if l == nil || len(l) != 0 {
			t.Fatalf("expected non-nil empty, got %v", l)
		}
	})
	t.Run("array", func(t *testing.T) {
		var l Listish
		if err := json.Unmarshal([]byte(`["a","b"]`), &l); err != nil {
			t.Fatal(err)
		}
		if len(l) != 2 {
			t.Fatalf("got %v", l)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		var l Listish
		err := json.Unmarshal([]byte(`123`), &l)
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestCov_Listish_IsZero(t *testing.T) {
	if !Listish(nil).IsZero() {
		t.Fatal("nil should be zero")
	}
	if (Listish{"a"}).IsZero() {
		t.Fatal("non-empty should not be zero")
	}
}

func TestCov_Listish_MarshalJSON(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		b, _ := Listish(nil).MarshalJSON()
		if string(b) != "null" {
			t.Fatalf("got %s", b)
		}
	})
	t.Run("single", func(t *testing.T) {
		b, _ := Listish{"x"}.MarshalJSON()
		if string(b) != `"x"` {
			t.Fatalf("got %s", b)
		}
	})
	t.Run("multiple", func(t *testing.T) {
		b, _ := Listish{"a", "b"}.MarshalJSON()
		if string(b) != `["a","b"]` {
			t.Fatalf("got %s", b)
		}
	})
}

// ============================================================
// types.go - SpaceDelimited
// ============================================================

func TestCov_SpaceDelimited_UnmarshalJSON(t *testing.T) {
	t.Run("values", func(t *testing.T) {
		var s SpaceDelimited
		json.Unmarshal([]byte(`"openid profile"`), &s)
		if len(s) != 2 || s[0] != "openid" {
			t.Fatalf("got %v", s)
		}
	})
	t.Run("empty", func(t *testing.T) {
		var s SpaceDelimited
		json.Unmarshal([]byte(`""`), &s)
		if s == nil {
			t.Fatal("expected non-nil empty SpaceDelimited, got nil")
		}
		if len(s) != 0 {
			t.Fatalf("expected empty, got %v", s)
		}
	})
	t.Run("invalid", func(t *testing.T) {
		var s SpaceDelimited
		if err := json.Unmarshal([]byte(`123`), &s); err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestCov_SpaceDelimited_MarshalJSON(t *testing.T) {
	t.Run("populated", func(t *testing.T) {
		b, _ := SpaceDelimited{"a", "b"}.MarshalJSON()
		if string(b) != `"a b"` {
			t.Fatalf("got %s", b)
		}
	})
	t.Run("nil", func(t *testing.T) {
		b, _ := SpaceDelimited(nil).MarshalJSON()
		if string(b) != `null` {
			t.Fatalf("expected null, got %s", b)
		}
	})
	t.Run("empty_non_nil", func(t *testing.T) {
		b, _ := (SpaceDelimited{}).MarshalJSON()
		if string(b) != `""` {
			t.Fatalf("expected empty string, got %s", b)
		}
	})
}

func TestCov_SpaceDelimited_IsZero(t *testing.T) {
	if !SpaceDelimited(nil).IsZero() {
		t.Fatal("nil should be zero")
	}
	if (SpaceDelimited{}).IsZero() {
		t.Fatal("non-nil empty should not be zero")
	}
	if (SpaceDelimited{"a"}).IsZero() {
		t.Fatal("populated should not be zero")
	}
}

func TestCov_SpaceDelimited_Omitzero(t *testing.T) {
	// Verify struct-level marshaling: nil scope omitted, empty scope present
	type tc struct {
		Scope SpaceDelimited `json:"scope,omitzero"`
	}

	// nil scope -> field omitted
	b, _ := json.Marshal(tc{Scope: nil})
	if strings.Contains(string(b), "scope") {
		t.Fatalf("nil scope should be omitted, got %s", b)
	}

	// non-nil empty scope -> "scope":""
	b, _ = json.Marshal(tc{Scope: SpaceDelimited{}})
	if !strings.Contains(string(b), `"scope":""`) {
		t.Fatalf("empty scope should marshal as empty string, got %s", b)
	}

	// populated scope -> "scope":"a b"
	b, _ = json.Marshal(tc{Scope: SpaceDelimited{"a", "b"}})
	if !strings.Contains(string(b), `"scope":"a b"`) {
		t.Fatalf("populated scope should marshal as space-separated, got %s", b)
	}
}

// ============================================================
// types.go - NullBool
// ============================================================

func TestCov_NullBool(t *testing.T) {
	t.Run("IsZero", func(t *testing.T) {
		if !(NullBool{}).IsZero() {
			t.Fatal("zero value should be zero")
		}
		if (NullBool{Bool: true, Valid: true}).IsZero() { //nolint
			t.Fatal("valid should not be zero")
		}
	})
	t.Run("MarshalJSON", func(t *testing.T) {
		b, _ := NullBool{}.MarshalJSON()
		if string(b) != "null" {
			t.Fatalf("got %s", b)
		}
		b, _ = NullBool{Bool: true, Valid: true}.MarshalJSON()
		if string(b) != "true" {
			t.Fatalf("got %s", b)
		}
		b, _ = NullBool{Bool: false, Valid: true}.MarshalJSON()
		if string(b) != "false" {
			t.Fatalf("got %s", b)
		}
	})
	t.Run("UnmarshalJSON", func(t *testing.T) {
		var nb NullBool
		json.Unmarshal([]byte("null"), &nb)
		if nb.Valid {
			t.Fatal("null should not be valid")
		}
		json.Unmarshal([]byte("true"), &nb)
		if !nb.Valid || !nb.Bool {
			t.Fatal("expected true")
		}
		json.Unmarshal([]byte("false"), &nb)
		if !nb.Valid || nb.Bool {
			t.Fatal("expected false")
		}
		if err := nb.UnmarshalJSON([]byte(`"yes"`)); err == nil {
			t.Fatal("expected error for string")
		}
	})
}

// ============================================================
// jwt.go
// ============================================================

func TestCov_DecodeRaw(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		// Build a valid token to decode
		pk := mustFromPrivate(t, mustEdKey(t))
		s := mustSigner(t, pk)
		tok := mustSignStr(t, s, goodClaims())
		raw, err := DecodeRaw(tok)
		if err != nil {
			t.Fatal(err)
		}
		if len(raw.Protected) == 0 || len(raw.Payload) == 0 || len(raw.Signature) == 0 {
			t.Fatal("expected non-empty segments")
		}
	})
	t.Run("empty", func(t *testing.T) {
		_, err := DecodeRaw("")
		if !errors.Is(err, ErrMalformedToken) {
			t.Fatalf("expected ErrMalformedToken, got %v", err)
		}
	})
	t.Run("two_parts", func(t *testing.T) {
		_, err := DecodeRaw("a.b")
		if !errors.Is(err, ErrMalformedToken) {
			t.Fatal("expected ErrMalformedToken")
		}
	})
	t.Run("four_parts", func(t *testing.T) {
		_, err := DecodeRaw("a.b.c.d")
		if !errors.Is(err, ErrMalformedToken) {
			t.Fatal("expected ErrMalformedToken")
		}
	})
	t.Run("bad_sig_base64", func(t *testing.T) {
		_, err := DecodeRaw("a.b.!!!invalid!!!")
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("expected ErrSignatureInvalid, got %v", err)
		}
	})
}

func TestCov_Decode(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		pk := mustFromPrivate(t, mustEdKey(t))
		s := mustSigner(t, pk)
		tok := mustSignStr(t, s, goodClaims())
		jws, err := Decode(tok)
		if err != nil {
			t.Fatal(err)
		}
		if jws.GetHeader().Alg != "EdDSA" {
			t.Fatalf("expected EdDSA, got %s", jws.GetHeader().Alg)
		}
	})
	t.Run("bad_token", func(t *testing.T) {
		_, err := Decode("bad")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("bad_header_json", func(t *testing.T) {
		// valid base64 but not valid JSON header
		badHdr := base64.RawURLEncoding.EncodeToString([]byte("not json"))
		payload := base64.RawURLEncoding.EncodeToString([]byte("{}"))
		sig := base64.RawURLEncoding.EncodeToString([]byte("sig"))
		_, err := Decode(badHdr + "." + payload + "." + sig)
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader, got %v", err)
		}
	})
}

func TestCov_UnmarshalClaims(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		raw := &RawJWT{
			Payload: []byte(base64.RawURLEncoding.EncodeToString([]byte(`{"iss":"x"}`))),
		}
		var tc TokenClaims
		if err := raw.UnmarshalClaims(&tc); err != nil {
			t.Fatal(err)
		}
		if tc.Iss != "x" {
			t.Fatalf("got %q", tc.Iss)
		}
	})
	t.Run("bad_base64", func(t *testing.T) {
		raw := &RawJWT{Payload: []byte("!!!")}
		err := raw.UnmarshalClaims(&TokenClaims{})
		if !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload, got %v", err)
		}
	})
	t.Run("bad_json", func(t *testing.T) {
		raw := &RawJWT{
			Payload: []byte(base64.RawURLEncoding.EncodeToString([]byte("not json"))),
		}
		err := raw.UnmarshalClaims(&TokenClaims{})
		if !errors.Is(err, ErrInvalidPayload) {
			t.Fatalf("expected ErrInvalidPayload, got %v", err)
		}
	})
}

func TestCov_UnmarshalHeader(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		hdrJSON := `{"alg":"EdDSA","kid":"k1","typ":"JWT"}`
		raw := &RawJWT{
			Protected: []byte(base64.RawURLEncoding.EncodeToString([]byte(hdrJSON))),
		}
		var h RFCHeader
		if err := raw.UnmarshalHeader(&h); err != nil {
			t.Fatal(err)
		}
		if h.Alg != "EdDSA" || h.KID != "k1" || h.Typ != "JWT" {
			t.Fatalf("got %+v", h)
		}
	})
	t.Run("bad_base64", func(t *testing.T) {
		raw := &RawJWT{Protected: []byte("!!!")}
		err := raw.UnmarshalHeader(&RFCHeader{})
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader, got %v", err)
		}
	})
	t.Run("bad_json", func(t *testing.T) {
		raw := &RawJWT{
			Protected: []byte(base64.RawURLEncoding.EncodeToString([]byte("not json"))),
		}
		err := raw.UnmarshalHeader(&RFCHeader{})
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader, got %v", err)
		}
	})
}

func TestCov_New(t *testing.T) {
	tc := goodClaims()
	jws, err := New(tc)
	if err != nil {
		t.Fatal(err)
	}
	h := jws.GetHeader()
	if h.Typ != "JWT" {
		t.Fatalf("expected JWT typ, got %q", h.Typ)
	}
}

func TestCov_New_BadClaims(t *testing.T) {
	_, err := New(&badClaims{Bad: make(chan int)})
	if err == nil {
		t.Fatal("expected marshal error")
	}
}

func TestCov_NewAccessToken(t *testing.T) {
	jws, err := NewAccessToken(goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	// SetTyp was called; header isn't re-parsed until SetHeader, but
	// the internal header.Typ should be "at+jwt"
	if jws.header.Typ != AccessTokenTyp {
		t.Fatalf("expected %q, got %q", AccessTokenTyp, jws.header.Typ)
	}
}

func TestCov_Encode(t *testing.T) {
	t.Run("unsigned_rejected", func(t *testing.T) {
		jws, _ := New(goodClaims())
		_, err := Encode(jws)
		if !errors.Is(err, ErrInvalidHeader) {
			t.Fatalf("expected ErrInvalidHeader, got %v", err)
		}
	})
	t.Run("signed_ok", func(t *testing.T) {
		pk := mustFromPrivate(t, mustEdKey(t))
		s := mustSigner(t, pk)
		jws, _ := s.Sign(goodClaims())
		str, err := Encode(jws)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Count(str, ".") != 2 {
			t.Fatal("expected 3 segments")
		}
	})
}

func TestCov_JWT_Encode(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	jws, _ := s.Sign(goodClaims())
	str, err := jws.Encode()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(str, ".") != 2 {
		t.Fatal("expected 3 segments")
	}
}

func TestCov_JWT_SetTyp(t *testing.T) {
	jws, _ := New(goodClaims())
	jws.SetTyp("at+jwt")
	if jws.header.Typ != "at+jwt" {
		t.Fatal("SetTyp did not work")
	}
}

func TestCov_JWT_SetHeader(t *testing.T) {
	jws, _ := New(goodClaims())
	h := RFCHeader{Alg: "EdDSA", KID: "k1", Typ: "JWT"}
	if err := jws.SetHeader(&h); err != nil {
		t.Fatal(err)
	}
	got := jws.GetHeader()
	if got.Alg != "EdDSA" || got.KID != "k1" {
		t.Fatalf("got %+v", got)
	}
}

func TestCov_RFCHeader_GetRFCHeader(t *testing.T) {
	h := &RFCHeader{Alg: "x"}
	if h.GetRFCHeader() != h {
		t.Fatal("expected same pointer")
	}
}

func TestCov_RawJWT_Accessors(t *testing.T) {
	raw := &RawJWT{
		Protected: []byte("p"),
		Payload:   []byte("a"),
		Signature: []byte("s"),
	}
	if string(raw.GetProtected()) != "p" {
		t.Fatal()
	}
	if string(raw.GetPayload()) != "a" {
		t.Fatal()
	}
	if string(raw.GetSignature()) != "s" {
		t.Fatal()
	}
	raw.SetSignature([]byte("s2"))
	if string(raw.Signature) != "s2" {
		t.Fatal()
	}
}

func TestCov_RawJWT_JSON(t *testing.T) {
	t.Run("round_trip", func(t *testing.T) {
		orig := &RawJWT{
			Protected: []byte("hdr"),
			Payload:   []byte("pay"),
			Signature: []byte{1, 2, 3},
		}
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatal(err)
		}
		var got RawJWT
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatal(err)
		}
		if string(got.Protected) != "hdr" || string(got.Payload) != "pay" {
			t.Fatalf("got %+v", got)
		}
	})
	t.Run("bad_json", func(t *testing.T) {
		var r RawJWT
		if err := r.UnmarshalJSON([]byte("not json")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("bad_sig_base64", func(t *testing.T) {
		var r RawJWT
		err := r.UnmarshalJSON([]byte(`{"protected":"a","payload":"b","signature":"!!!"}`))
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestCov_SetClaims(t *testing.T) {
	raw := &RawJWT{}
	tc := goodClaims()
	if err := raw.SetClaims(tc); err != nil {
		t.Fatal(err)
	}
	if len(raw.Payload) == 0 {
		t.Fatal("expected non-empty payload")
	}
}

func TestCov_SetClaims_Bad(t *testing.T) {
	raw := &RawJWT{}
	err := raw.SetClaims(&badClaims{Bad: make(chan int)})
	if err == nil {
		t.Fatal("expected error")
	}
}

// ============================================================
// jwa.go
// ============================================================

func TestCov_ecInfo(t *testing.T) {
	for _, tc := range []struct {
		curve elliptic.Curve
		alg   string
	}{
		{elliptic.P256(), "ES256"},
		{elliptic.P384(), "ES384"},
		{elliptic.P521(), "ES512"},
	} {
		ci, err := ecInfo(tc.curve)
		if err != nil {
			t.Fatal(err)
		}
		if ci.Alg != tc.alg {
			t.Fatalf("expected %s, got %s", tc.alg, ci.Alg)
		}
	}
	// unsupported curve - use a custom curve params
	badCurve := &elliptic.CurveParams{Name: "bad", BitSize: 128}
	_, err := ecInfo(badCurve)
	if !errors.Is(err, ErrUnsupportedCurve) {
		t.Fatalf("expected ErrUnsupportedCurve, got %v", err)
	}
}

func TestCov_ecInfoByCrv(t *testing.T) {
	for _, crv := range []string{"P-256", "P-384", "P-521"} {
		if _, err := ecInfoByCrv(crv); err != nil {
			t.Fatal(err)
		}
	}
	_, err := ecInfoByCrv("P-192")
	if !errors.Is(err, ErrUnsupportedCurve) {
		t.Fatal("expected ErrUnsupportedCurve")
	}
}

func TestCov_ecInfoForAlg(t *testing.T) {
	t.Run("match", func(t *testing.T) {
		ci, err := ecInfoForAlg(elliptic.P256(), "ES256")
		if err != nil || ci.Alg != "ES256" {
			t.Fatal("expected match")
		}
	})
	t.Run("mismatch", func(t *testing.T) {
		_, err := ecInfoForAlg(elliptic.P256(), "ES384")
		if !errors.Is(err, ErrAlgConflict) {
			t.Fatal("expected ErrAlgConflict")
		}
	})
	t.Run("bad_curve", func(t *testing.T) {
		badCurve := &elliptic.CurveParams{Name: "bad", BitSize: 128}
		_, err := ecInfoForAlg(badCurve, "ES256")
		if !errors.Is(err, ErrUnsupportedCurve) {
			t.Fatal("expected ErrUnsupportedCurve")
		}
	})
}

func TestCov_signingParams(t *testing.T) {
	t.Run("EC", func(t *testing.T) {
		k := mustECKey(t, elliptic.P256())
		alg, hash, ecKeySize, err := signingParams(k)
		if err != nil || alg != "ES256" || hash != crypto.SHA256 || ecKeySize != 32 {
			t.Fatalf("got %s %v %d %v", alg, hash, ecKeySize, err)
		}
	})
	t.Run("RSA", func(t *testing.T) {
		k := mustRSAKey(t)
		alg, hash, ecKeySize, err := signingParams(k)
		if err != nil || alg != "RS256" || hash != crypto.SHA256 || ecKeySize != 0 {
			t.Fatalf("got %s %v %d %v", alg, hash, ecKeySize, err)
		}
	})
	t.Run("Ed25519", func(t *testing.T) {
		k := mustEdKey(t)
		alg, hash, ecKeySize, err := signingParams(k)
		if err != nil || alg != "EdDSA" || hash != 0 || ecKeySize != 0 {
			t.Fatalf("got %s %v %d %v", alg, hash, ecKeySize, err)
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		_, _, _, err := signingParams(fakeSigner{pub: fakeKey{}})
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatal("expected ErrUnsupportedKeyType")
		}
	})
}

func TestCov_signingInputBytes(t *testing.T) {
	out := signingInputBytes([]byte("hdr"), []byte("pay"))
	if string(out) != "hdr.pay" {
		t.Fatalf("got %q", out)
	}
}

func TestCov_digestFor(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		d, err := digestFor(crypto.SHA256, []byte("hello"))
		if err != nil || len(d) != 32 {
			t.Fatal(err)
		}
	})
	t.Run("unavailable", func(t *testing.T) {
		_, err := digestFor(crypto.Hash(99), []byte("hello"))
		if !errors.Is(err, ErrUnsupportedAlg) {
			t.Fatal("expected ErrUnsupportedAlg")
		}
	})
}

func TestCov_ecdsaDERToP1363(t *testing.T) {
	keySize := 32
	t.Run("valid", func(t *testing.T) {
		type ecSig struct{ R, S *big.Int }
		der, _ := asn1.Marshal(ecSig{big.NewInt(42), big.NewInt(99)})
		out, err := ecdsaDERToP1363(der, keySize)
		if err != nil || len(out) != 2*keySize {
			t.Fatalf("err=%v len=%d", err, len(out))
		}
	})
	t.Run("bad_asn1", func(t *testing.T) {
		_, err := ecdsaDERToP1363([]byte{0xff}, keySize)
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("trailing_bytes", func(t *testing.T) {
		type ecSig struct{ R, S *big.Int }
		der, _ := asn1.Marshal(ecSig{big.NewInt(1), big.NewInt(1)})
		der = append(der, 0x00) // trailing byte
		_, err := ecdsaDERToP1363(der, keySize)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("expected ErrSignatureInvalid, got %v", err)
		}
	})
	t.Run("R_too_large", func(t *testing.T) {
		type ecSig struct{ R, S *big.Int }
		bigR := new(big.Int).SetBytes(make([]byte, keySize+1))
		bigR.SetBit(bigR, (keySize+1)*8-1, 1) // ensure it's keySize+1 bytes
		der, _ := asn1.Marshal(ecSig{bigR, big.NewInt(1)})
		_, err := ecdsaDERToP1363(der, keySize)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("expected ErrSignatureInvalid, got %v", err)
		}
	})
}

// ============================================================
// jwk.go
// ============================================================

func TestCov_KeyType(t *testing.T) {
	ec := mustECKey(t, elliptic.P256())
	rs := mustRSAKey(t)
	ed := mustEdKey(t)
	tests := []struct {
		key    CryptoPublicKey
		expect string
	}{
		{&ec.PublicKey, "EC"},
		{&rs.PublicKey, "RSA"},
		{ed.Public().(ed25519.PublicKey), "OKP"},
		{fakeKey{}, ""},
	}
	for _, tt := range tests {
		pk := PublicKey{Key: tt.key}
		if got := pk.KeyType(); got != tt.expect {
			t.Errorf("KeyType(%T)=%q want %q", tt.key, got, tt.expect)
		}
	}
}

func TestCov_PublicKey_JSON_AllTypes(t *testing.T) {
	for _, name := range []string{"EC", "RSA", "Ed25519"} {
		t.Run(name, func(t *testing.T) {
			var pub crypto.PublicKey
			switch name {
			case "EC":
				pub = &mustECKey(t, elliptic.P256()).PublicKey
			case "RSA":
				pub = &mustRSAKey(t).PublicKey
			case "Ed25519":
				pub = mustEdKey(t).Public()
			}
			pk, err := FromPublicKey(pub)
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(pk)
			if err != nil {
				t.Fatal(err)
			}
			var decoded PublicKey
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.KID != pk.KID {
				t.Fatalf("KID mismatch: %q vs %q", decoded.KID, pk.KID)
			}
		})
	}
}

func TestCov_PublicKey_UnmarshalJSON_Errors(t *testing.T) {
	t.Run("bad_json", func(t *testing.T) {
		var pk PublicKey
		if err := pk.UnmarshalJSON([]byte("not json")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("unknown_kty", func(t *testing.T) {
		var pk PublicKey
		err := pk.UnmarshalJSON([]byte(`{"kty":"UNKNOWN"}`))
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
		}
	})
}

func TestCov_PrivateKey_JSON_AllTypes(t *testing.T) {
	for _, name := range []string{"EC", "RSA", "Ed25519"} {
		t.Run(name, func(t *testing.T) {
			var signer crypto.Signer
			switch name {
			case "EC":
				signer = mustECKey(t, elliptic.P384())
			case "RSA":
				signer = mustRSAKey(t)
			case "Ed25519":
				signer = mustEdKey(t)
			}
			pk, err := FromPrivateKey(signer, "test-kid")
			if err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(pk)
			if err != nil {
				t.Fatal(err)
			}
			var decoded PrivateKey
			if err := json.Unmarshal(data, &decoded); err != nil {
				t.Fatal(err)
			}
			if decoded.KID != pk.KID {
				t.Fatalf("KID mismatch: %q vs %q", decoded.KID, pk.KID)
			}
		})
	}
}

func TestCov_PrivateKey_UnmarshalJSON_Errors(t *testing.T) {
	t.Run("bad_json", func(t *testing.T) {
		var pk PrivateKey
		if err := pk.UnmarshalJSON([]byte("not json")); err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("missing_d", func(t *testing.T) {
		var pk PrivateKey
		err := pk.UnmarshalJSON([]byte(`{"kty":"EC","crv":"P-256","x":"a","y":"b"}`))
		if !errors.Is(err, ErrMissingKeyData) {
			t.Fatalf("expected ErrMissingKeyData, got %v", err)
		}
	})
}

func TestCov_Thumbprint(t *testing.T) {
	for _, name := range []string{"EC", "RSA", "Ed25519"} {
		t.Run(name, func(t *testing.T) {
			var pub crypto.PublicKey
			switch name {
			case "EC":
				pub = &mustECKey(t, elliptic.P521()).PublicKey
			case "RSA":
				pub = &mustRSAKey(t).PublicKey
			case "Ed25519":
				pub = mustEdKey(t).Public()
			}
			pk, _ := FromPublicKey(pub)
			thumb, err := pk.Thumbprint()
			if err != nil || thumb == "" {
				t.Fatalf("err=%v thumb=%q", err, thumb)
			}
			// deterministic
			thumb2, _ := pk.Thumbprint()
			if thumb != thumb2 {
				t.Fatal("not deterministic")
			}
		})
	}
	t.Run("unsupported", func(t *testing.T) {
		pk := PublicKey{Key: fakeKey{}}
		_, err := pk.Thumbprint()
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
		}
	})
}

func TestCov_PrivateKey_Thumbprint(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	thumb, err := pk.Thumbprint()
	if err != nil || thumb == "" {
		t.Fatal(err)
	}
}

func TestCov_PrivateKey_PublicKey(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		pk := mustFromPrivate(t, mustEdKey(t))
		pub, err := pk.PublicKey()
		if err != nil {
			t.Fatal(err)
		}
		if pub.KID != pk.KID {
			t.Fatal("KID mismatch")
		}
	})
	t.Run("bad_signer", func(t *testing.T) {
		// signer whose Public() returns a non-CryptoPublicKey
		pk := &PrivateKey{privKey: fakeSigner{pub: "not a key"}}
		_, err := pk.PublicKey()
		if !errors.Is(err, ErrSanityFail) {
			t.Fatalf("expected ErrSanityFail, got %v", err)
		}
	})
}

func TestCov_NewPrivateKey(t *testing.T) {
	pk, err := NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	if pk.KID == "" {
		t.Fatal("expected auto KID")
	}
	// Should be Ed25519
	if _, ok := pk.privKey.(ed25519.PrivateKey); !ok {
		t.Fatalf("expected Ed25519, got %T", pk.privKey)
	}
}

func TestCov_FromPublicKey(t *testing.T) {
	t.Run("EC", func(t *testing.T) {
		pk, err := FromPublicKey(&mustECKey(t, elliptic.P256()).PublicKey)
		if err != nil || pk.Alg != "ES256" {
			t.Fatalf("err=%v alg=%s", err, pk.Alg)
		}
	})
	t.Run("RSA", func(t *testing.T) {
		pk, err := FromPublicKey(&mustRSAKey(t).PublicKey)
		if err != nil || pk.Alg != "RS256" {
			t.Fatalf("err=%v alg=%s", err, pk.Alg)
		}
	})
	t.Run("Ed25519", func(t *testing.T) {
		pk, err := FromPublicKey(mustEdKey(t).Public())
		if err != nil || pk.Alg != "EdDSA" {
			t.Fatalf("err=%v alg=%s", err, pk.Alg)
		}
	})
	t.Run("not_crypto_key", func(t *testing.T) {
		_, err := FromPublicKey("not a key")
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatal("expected ErrUnsupportedKeyType")
		}
	})
	t.Run("unsupported_crypto_key", func(t *testing.T) {
		_, err := FromPublicKey(fakeKey{})
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatal("expected ErrUnsupportedKeyType")
		}
	})
}

func TestCov_FromPrivateKey(t *testing.T) {
	t.Run("happy", func(t *testing.T) {
		pk, err := FromPrivateKey(mustEdKey(t), "my-kid")
		if err != nil || pk.KID != "my-kid" || pk.Alg != "EdDSA" {
			t.Fatalf("err=%v kid=%s alg=%s", err, pk.KID, pk.Alg)
		}
	})
	t.Run("unsupported", func(t *testing.T) {
		_, err := FromPrivateKey(fakeSigner{pub: fakeKey{}}, "")
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatal("expected ErrUnsupportedKeyType")
		}
	})
}

func TestCov_ParseJWK(t *testing.T) {
	// Generate a key, marshal it, parse it back
	ed := mustEdKey(t)
	pk, _ := FromPublicKey(ed.Public())
	data, _ := json.Marshal(pk)

	t.Run("ParsePublicJWK", func(t *testing.T) {
		got, err := ParsePublicJWK(data)
		if err != nil || got.KID != pk.KID {
			t.Fatalf("err=%v kid=%s", err, got.KID)
		}
	})

	// Private key
	priv, _ := FromPrivateKey(ed, "k1")
	privData, _ := json.Marshal(priv)

	t.Run("ParsePrivateJWK", func(t *testing.T) {
		got, err := ParsePrivateJWK(privData)
		if err != nil || got.KID != "k1" {
			t.Fatalf("err=%v kid=%s", err, got.KID)
		}
	})

	t.Run("ParseWellKnownJWKs", func(t *testing.T) {
		jwksData := fmt.Sprintf(`{"keys":[%s]}`, string(data))
		got, err := ParseWellKnownJWKs([]byte(jwksData))
		if err != nil || len(got.Keys) != 1 {
			t.Fatalf("err=%v len=%d", err, len(got.Keys))
		}
	})
}

func TestCov_decodeRSA_Errors(t *testing.T) {
	t.Run("bad_n", func(t *testing.T) {
		_, err := decodeRSA(rawKey{Kty: "RSA", N: "!!!", E: "AQAB"})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("bad_e", func(t *testing.T) {
		_, err := decodeRSA(rawKey{Kty: "RSA", N: "AAAA", E: "!!!"})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("exponent_too_small", func(t *testing.T) {
		// e=1
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(1).Bytes())
		n := base64.RawURLEncoding.EncodeToString(make([]byte, 256))
		_, err := decodeRSA(rawKey{Kty: "RSA", N: n, E: e})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("exponent_too_large_32bit", func(t *testing.T) {
		// e > MaxInt32 but fits in int64
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(1<<31 + 1).Bytes())
		n := base64.RawURLEncoding.EncodeToString(make([]byte, 256))
		_, err := decodeRSA(rawKey{Kty: "RSA", N: n, E: e})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("exponent_too_large_int64", func(t *testing.T) {
		// e that doesn't fit in int64
		bigE := new(big.Int).Lsh(big.NewInt(1), 64)
		e := base64.RawURLEncoding.EncodeToString(bigE.Bytes())
		n := base64.RawURLEncoding.EncodeToString(make([]byte, 256))
		_, err := decodeRSA(rawKey{Kty: "RSA", N: n, E: e})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("key_too_small", func(t *testing.T) {
		// 512-bit key
		n := base64.RawURLEncoding.EncodeToString(make([]byte, 64))
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())
		_, err := decodeRSA(rawKey{Kty: "RSA", N: n, E: e})
		if !errors.Is(err, ErrKeyTooSmall) {
			t.Fatalf("expected ErrKeyTooSmall, got %v", err)
		}
	})
}

func TestCov_decodeEC_Errors(t *testing.T) {
	zeros32 := base64.RawURLEncoding.EncodeToString(make([]byte, 32))
	t.Run("bad_x", func(t *testing.T) {
		_, err := decodeEC(rawKey{Kty: "EC", Crv: "P-256", X: "!!!", Y: zeros32})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("bad_y", func(t *testing.T) {
		_, err := decodeEC(rawKey{Kty: "EC", Crv: "P-256", X: zeros32, Y: "!!!"})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("unsupported_crv", func(t *testing.T) {
		_, err := decodeEC(rawKey{Kty: "EC", Crv: "P-192", X: zeros32, Y: zeros32})
		if !errors.Is(err, ErrUnsupportedCurve) {
			t.Fatalf("expected ErrUnsupportedCurve, got %v", err)
		}
	})
	t.Run("x_too_long", func(t *testing.T) {
		longX := base64.RawURLEncoding.EncodeToString(make([]byte, 33))
		_, err := decodeEC(rawKey{Kty: "EC", Crv: "P-256", X: longX, Y: zeros32})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("y_too_long", func(t *testing.T) {
		longY := base64.RawURLEncoding.EncodeToString(make([]byte, 33))
		_, err := decodeEC(rawKey{Kty: "EC", Crv: "P-256", X: zeros32, Y: longY})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("not_on_curve", func(t *testing.T) {
		// (0, 0) is not on P-256
		_, err := decodeEC(rawKey{Kty: "EC", Crv: "P-256", X: zeros32, Y: zeros32})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
}

func TestCov_decodeOKP_Errors(t *testing.T) {
	t.Run("wrong_crv", func(t *testing.T) {
		_, err := decodeOKP(rawKey{Kty: "OKP", Crv: "X25519"})
		if !errors.Is(err, ErrUnsupportedCurve) {
			t.Fatalf("expected ErrUnsupportedCurve, got %v", err)
		}
	})
	t.Run("bad_x", func(t *testing.T) {
		_, err := decodeOKP(rawKey{Kty: "OKP", Crv: "Ed25519", X: "!!!"})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("wrong_size", func(t *testing.T) {
		x := base64.RawURLEncoding.EncodeToString(make([]byte, 31))
		_, err := decodeOKP(rawKey{Kty: "OKP", Crv: "Ed25519", X: x})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
}

func TestCov_decodePrivate_Errors(t *testing.T) {
	t.Run("missing_d", func(t *testing.T) {
		_, err := decodePrivate(rawKey{Kty: "EC", Crv: "P-256"})
		if !errors.Is(err, ErrMissingKeyData) {
			t.Fatalf("expected ErrMissingKeyData, got %v", err)
		}
	})
	t.Run("unknown_kty", func(t *testing.T) {
		_, err := decodePrivate(rawKey{Kty: "UNKNOWN", D: "AA"})
		if !errors.Is(err, ErrUnsupportedKeyType) {
			t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
		}
	})
	t.Run("OKP_wrong_crv", func(t *testing.T) {
		_, err := decodePrivate(rawKey{Kty: "OKP", Crv: "X25519", D: "AA"})
		if !errors.Is(err, ErrUnsupportedCurve) {
			t.Fatalf("expected ErrUnsupportedCurve, got %v", err)
		}
	})
	t.Run("Ed25519_wrong_seed_size", func(t *testing.T) {
		d := base64.RawURLEncoding.EncodeToString(make([]byte, 31))
		_, err := decodePrivate(rawKey{Kty: "OKP", Crv: "Ed25519", D: d})
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
	t.Run("EC_bad_d", func(t *testing.T) {
		_, err := decodePrivate(rawKey{Kty: "EC", Crv: "P-256", D: "!!!"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("RSA_bad_d", func(t *testing.T) {
		n := base64.RawURLEncoding.EncodeToString(make([]byte, 256))
		e := base64.RawURLEncoding.EncodeToString(big.NewInt(65537).Bytes())
		_, err := decodePrivate(rawKey{Kty: "RSA", N: n, E: e, D: "!!!"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("OKP_bad_d", func(t *testing.T) {
		_, err := decodePrivate(rawKey{Kty: "OKP", Crv: "Ed25519", D: "!!!"})
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("auto_kid", func(t *testing.T) {
		// Valid Ed25519 private key with no KID - should auto-compute
		seed := make([]byte, ed25519.SeedSize)
		rand.Read(seed)
		d := base64.RawURLEncoding.EncodeToString(seed)
		x := base64.RawURLEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey))
		pk, err := decodePrivate(rawKey{Kty: "OKP", Crv: "Ed25519", D: d, X: x})
		if err != nil {
			t.Fatal(err)
		}
		if pk.KID == "" {
			t.Fatal("expected auto KID")
		}
	})
}

func TestCov_decodeOne_AutoKID(t *testing.T) {
	// decodeOne with no kid should auto-compute from thumbprint
	pub := mustEdKey(t).Public().(ed25519.PublicKey)
	x := base64.RawURLEncoding.EncodeToString([]byte(pub))
	pk, err := decodeOne(rawKey{Kty: "OKP", Crv: "Ed25519", X: x})
	if err != nil {
		t.Fatal(err)
	}
	if pk.KID == "" {
		t.Fatal("expected auto KID")
	}
}

func TestCov_decodeB64Field(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		b, err := decodeB64Field("EC", "kid1", "d", base64.RawURLEncoding.EncodeToString([]byte{1, 2, 3}))
		if err != nil || len(b) != 3 {
			t.Fatal(err)
		}
	})
	t.Run("bad_base64", func(t *testing.T) {
		_, err := decodeB64Field("EC", "kid1", "d", "!!!")
		if !errors.Is(err, ErrInvalidKey) {
			t.Fatalf("expected ErrInvalidKey, got %v", err)
		}
	})
}

func TestCov_toPublicKeyOps(t *testing.T) {
	tests := []struct {
		in     []string
		expect []string
	}{
		{nil, nil},
		{[]string{"sign"}, []string{"verify"}},
		{[]string{"decrypt"}, []string{"encrypt"}},
		{[]string{"unwrapKey"}, []string{"wrapKey"}},
		{[]string{"verify", "encrypt", "wrapKey"}, []string{"verify", "encrypt", "wrapKey"}},
		{[]string{"deriveKey"}, nil}, // unrecognized ops dropped
	}
	for _, tt := range tests {
		got := toPublicKeyOps(tt.in)
		if len(got) != len(tt.expect) {
			t.Errorf("toPublicKeyOps(%v)=%v want %v", tt.in, got, tt.expect)
		}
	}
}

func TestCov_encode_Unsupported(t *testing.T) {
	_, err := encode(PublicKey{Key: fakeKey{}})
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
	}
}

func TestCov_encodePrivate_Unsupported(t *testing.T) {
	// Signer whose Public() returns a real ed25519 key but signer type is custom
	edKey := mustEdKey(t)
	pk := PrivateKey{
		privKey: fakeSigner{pub: edKey.Public()},
		KID:     "test",
	}
	_, err := encodePrivate(pk)
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
	}
}

func TestCov_encodePrivate_RSA_NoPrimes(t *testing.T) {
	rsaKey := mustRSAKey(t)
	rsaKey.Primes = nil // remove primes
	pk := PrivateKey{privKey: rsaKey, KID: "test"}
	rk, err := encodePrivate(pk)
	if err != nil {
		t.Fatal(err)
	}
	// Should have D but no P/Q
	if rk.D == "" {
		t.Fatal("expected D")
	}
	if rk.P != "" || rk.Q != "" {
		t.Fatal("expected no P/Q without primes")
	}
}

// ============================================================
// sign.go
// ============================================================

func TestCov_NewSigner(t *testing.T) {
	t.Run("empty_keys", func(t *testing.T) {
		_, err := NewSigner(nil)
		if !errors.Is(err, ErrNoSigningKey) {
			t.Fatal("expected ErrNoSigningKey")
		}
	})
	t.Run("nil_key", func(t *testing.T) {
		_, err := NewSigner([]*PrivateKey{nil})
		if !errors.Is(err, ErrNoSigningKey) {
			t.Fatal("expected ErrNoSigningKey")
		}
	})
	t.Run("nil_privkey", func(t *testing.T) {
		_, err := NewSigner([]*PrivateKey{{}})
		if !errors.Is(err, ErrNoSigningKey) {
			t.Fatal("expected ErrNoSigningKey")
		}
	})
	t.Run("alg_conflict", func(t *testing.T) {
		pk := mustFromPrivate(t, mustEdKey(t))
		pk.Alg = "RS256" // wrong alg for Ed25519
		_, err := NewSigner([]*PrivateKey{pk})
		if !errors.Is(err, ErrAlgConflict) {
			t.Fatalf("expected ErrAlgConflict, got %v", err)
		}
	})
	t.Run("wrong_use", func(t *testing.T) {
		pk := mustFromPrivate(t, mustEdKey(t))
		pk.Use = "enc"
		_, err := NewSigner([]*PrivateKey{pk})
		if err == nil {
			t.Fatal("expected error for use=enc")
		}
	})
	t.Run("auto_kid", func(t *testing.T) {
		pk := mustFromPrivate(t, mustEdKey(t))
		pk.KID = "" // clear to trigger auto-compute
		s, err := NewSigner([]*PrivateKey{pk})
		if err != nil {
			t.Fatal(err)
		}
		if s.keys[0].KID == "" {
			t.Fatal("expected auto KID")
		}
	})
	t.Run("multiple_keys", func(t *testing.T) {
		pk1 := mustFromPrivate(t, mustEdKey(t))
		pk2 := mustFromPrivate(t, mustECKey(t, elliptic.P256()))
		s, err := NewSigner([]*PrivateKey{pk1, pk2})
		if err != nil {
			t.Fatal(err)
		}
		if len(s.keys) != 2 {
			t.Fatal("expected 2 keys")
		}
	})
	t.Run("retired_keys", func(t *testing.T) {
		pk := mustFromPrivate(t, mustEdKey(t))
		retired, _ := FromPublicKey(mustEdKey(t).Public())
		s, err := NewSigner([]*PrivateKey{pk}, *retired)
		if err != nil {
			t.Fatal(err)
		}
		if len(s.Keys) != 2 {
			t.Fatalf("expected 2 JWKS keys, got %d", len(s.Keys))
		}
	})
}

func TestCov_SignJWT(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)

	t.Run("happy", func(t *testing.T) {
		jws, _ := New(goodClaims())
		if err := s.SignJWT(jws); err != nil {
			t.Fatal(err)
		}
		if jws.GetHeader().Alg != "EdDSA" {
			t.Fatal("expected EdDSA")
		}
	})
	t.Run("with_kid", func(t *testing.T) {
		jws, _ := New(goodClaims())
		jws.header.KID = pk.KID
		if err := s.SignJWT(jws); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown_kid", func(t *testing.T) {
		jws, _ := New(goodClaims())
		jws.header.KID = "nonexistent"
		err := s.SignJWT(jws)
		if !errors.Is(err, ErrUnknownKID) {
			t.Fatalf("expected ErrUnknownKID, got %v", err)
		}
	})
	t.Run("alg_conflict", func(t *testing.T) {
		jws, _ := New(goodClaims())
		jws.header.Alg = "RS256"
		err := s.SignJWT(jws)
		if !errors.Is(err, ErrAlgConflict) {
			t.Fatalf("expected ErrAlgConflict, got %v", err)
		}
	})
	t.Run("nil_privkey", func(t *testing.T) {
		// Construct signer directly (bypass NewSigner validation)
		bad := &Signer{keys: []PrivateKey{{KID: "test"}}}
		jws, _ := New(goodClaims())
		err := bad.SignJWT(jws)
		if !errors.Is(err, ErrNoSigningKey) {
			t.Fatalf("expected ErrNoSigningKey, got %v", err)
		}
	})
}

func TestCov_SignRaw(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)

	t.Run("happy", func(t *testing.T) {
		hdr := &RFCHeader{Typ: "JWT"}
		raw, err := s.SignRaw(hdr, []byte(`{"sub":"user"}`))
		if err != nil {
			t.Fatal(err)
		}
		if len(raw.Signature) == 0 {
			t.Fatal("expected signature")
		}
	})
	t.Run("nil_payload", func(t *testing.T) {
		hdr := &RFCHeader{Typ: "JWT"}
		raw, err := s.SignRaw(hdr, nil)
		if err != nil {
			t.Fatal(err)
		}
		if raw.Payload == nil {
			t.Fatal("expected non-nil payload")
		}
	})
	t.Run("alg_conflict", func(t *testing.T) {
		hdr := &RFCHeader{Alg: "RS256"}
		_, err := s.SignRaw(hdr, nil)
		if !errors.Is(err, ErrAlgConflict) {
			t.Fatal("expected ErrAlgConflict")
		}
	})
}

func TestCov_Sign(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	jws, err := s.Sign(goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	if jws.GetHeader().Alg != "EdDSA" {
		t.Fatal("expected EdDSA")
	}
}

func TestCov_SignToString(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	tok, err := s.SignToString(goodClaims())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(tok, ".") != 2 {
		t.Fatal("expected 3 segments")
	}
}

func TestCov_Signer_Verifier(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	v := s.Verifier()
	if v == nil {
		t.Fatal("expected verifier")
	}
	// Should work for round-trip
	tok := mustSignStr(t, s, goodClaims())
	if _, err := v.VerifyJWT(tok); err != nil {
		t.Fatal(err)
	}
}

func TestCov_RoundRobin(t *testing.T) {
	pk1 := mustFromPrivate(t, mustEdKey(t))
	pk2 := mustFromPrivate(t, mustECKey(t, elliptic.P256()))
	s := mustSigner(t, pk1, pk2)

	// Sign twice, should use different keys
	tok1 := mustSignStr(t, s, goodClaims())
	tok2 := mustSignStr(t, s, goodClaims())
	jws1, _ := Decode(tok1)
	jws2, _ := Decode(tok2)
	if jws1.GetHeader().KID == jws2.GetHeader().KID {
		t.Fatal("expected different KIDs from round-robin")
	}
}

// ============================================================
// verify.go
// ============================================================

func TestCov_NewVerifier(t *testing.T) {
	ed := mustEdKey(t)
	pub, _ := FromPublicKey(ed.Public())

	t.Run("happy", func(t *testing.T) {
		v, err := NewVerifier([]PublicKey{*pub})
		if err != nil || len(v.pubKeys) != 1 {
			t.Fatal(err)
		}
	})
	t.Run("dedup", func(t *testing.T) {
		v, err := NewVerifier([]PublicKey{*pub, *pub})
		if err != nil || len(v.pubKeys) != 1 {
			t.Fatalf("expected dedup to 1, got %d", len(v.pubKeys))
		}
	})
	t.Run("nil_rejected", func(t *testing.T) {
		_, err := NewVerifier(nil)
		if !errors.Is(err, ErrNoVerificationKey) {
			t.Fatalf("expected ErrNoVerificationKey, got %v", err)
		}
	})
	t.Run("empty_rejected", func(t *testing.T) {
		_, err := NewVerifier([]PublicKey{})
		if !errors.Is(err, ErrNoVerificationKey) {
			t.Fatalf("expected ErrNoVerificationKey, got %v", err)
		}
	})
	t.Run("same_kid_different_keys", func(t *testing.T) {
		// Two different keys with the same KID should both be kept
		pub1, _ := FromPublicKey(mustEdKey(t).Public())
		pub2, _ := FromPublicKey(mustEdKey(t).Public())
		pub1.KID = "shared"
		pub2.KID = "shared"
		v, err := NewVerifier([]PublicKey{*pub1, *pub2})
		if err != nil {
			t.Fatal(err)
		}
		if len(v.pubKeys) != 2 {
			t.Fatalf("expected 2 keys (same KID, different material), got %d", len(v.pubKeys))
		}
	})
}

func TestCov_PublicKeys(t *testing.T) {
	ed := mustEdKey(t)
	pub, _ := FromPublicKey(ed.Public())
	v, _ := NewVerifier([]PublicKey{*pub})
	keys := v.PublicKeys()
	if len(keys) != 1 {
		t.Fatal("expected 1 key")
	}
}

func TestCov_Verify(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	tok := mustSignStr(t, s, goodClaims())

	t.Run("happy", func(t *testing.T) {
		jws, _ := Decode(tok)
		v := s.Verifier()
		if err := v.Verify(jws); err != nil {
			t.Fatal(err)
		}
	})
	t.Run("unknown_kid", func(t *testing.T) {
		jws, _ := Decode(tok)
		other, _ := FromPublicKey(mustEdKey(t).Public())
		v, _ := NewVerifier([]PublicKey{*other})
		err := v.Verify(jws)
		if !errors.Is(err, ErrUnknownKID) {
			t.Fatalf("expected ErrUnknownKID, got %v", err)
		}
	})
	t.Run("wrong_key_matching_kid", func(t *testing.T) {
		// Verifier has a key with the same KID but different material
		jws, _ := Decode(tok)
		kid := jws.GetHeader().KID

		other, _ := FromPublicKey(mustEdKey(t).Public())
		other.KID = kid // same KID, different key material
		v, _ := NewVerifier([]PublicKey{*other})
		err := v.Verify(jws)
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatalf("expected ErrSignatureInvalid, got %v", err)
		}
	})
}

func TestCov_verifyOneKey_AllAlgs(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signer crypto.Signer
	}{
		{"ES256", mustECKey(t, elliptic.P256())},
		{"ES384", mustECKey(t, elliptic.P384())},
		{"ES512", mustECKey(t, elliptic.P521())},
		{"RS256", mustRSAKey(t)},
		{"EdDSA", mustEdKey(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pk := mustFromPrivate(t, tc.signer)
			s := mustSigner(t, pk)
			tok := mustSignStr(t, s, goodClaims())
			v := s.Verifier()
			jws, _ := Decode(tok)
			if err := v.Verify(jws); err != nil {
				t.Fatal(err)
			}
		})
	}

	t.Run("unsupported_alg", func(t *testing.T) {
		h := RFCHeader{Alg: "HS256", KID: "k"}
		err := verifyOneKey(h, mustEdKey(t).Public().(ed25519.PublicKey), []byte("input"), []byte("sig"))
		if !errors.Is(err, ErrUnsupportedAlg) {
			t.Fatal("expected ErrUnsupportedAlg")
		}
	})

	t.Run("wrong_key_type_EC", func(t *testing.T) {
		h := RFCHeader{Alg: "ES256", KID: "k"}
		err := verifyOneKey(h, mustEdKey(t).Public().(ed25519.PublicKey), []byte("input"), []byte("sig"))
		if !errors.Is(err, ErrAlgConflict) {
			t.Fatal("expected ErrAlgConflict")
		}
	})

	t.Run("wrong_key_type_RSA", func(t *testing.T) {
		h := RFCHeader{Alg: "RS256", KID: "k"}
		err := verifyOneKey(h, mustEdKey(t).Public().(ed25519.PublicKey), []byte("input"), []byte("sig"))
		if !errors.Is(err, ErrAlgConflict) {
			t.Fatal("expected ErrAlgConflict")
		}
	})

	t.Run("wrong_key_type_EdDSA", func(t *testing.T) {
		h := RFCHeader{Alg: "EdDSA", KID: "k"}
		err := verifyOneKey(h, &mustRSAKey(t).PublicKey, []byte("input"), []byte("sig"))
		if !errors.Is(err, ErrAlgConflict) {
			t.Fatal("expected ErrAlgConflict")
		}
	})

	t.Run("EC_wrong_sig_length", func(t *testing.T) {
		h := RFCHeader{Alg: "ES256", KID: "k"}
		err := verifyOneKey(h, &mustECKey(t, elliptic.P256()).PublicKey, []byte("input"), []byte("short"))
		if !errors.Is(err, ErrSignatureInvalid) {
			t.Fatal("expected ErrSignatureInvalid")
		}
	})
}

func TestCov_VerifyJWT(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	tok := mustSignStr(t, s, goodClaims())
	v := s.Verifier()

	t.Run("happy", func(t *testing.T) {
		jws, err := v.VerifyJWT(tok)
		if err != nil {
			t.Fatal(err)
		}
		if jws.GetHeader().Alg != "EdDSA" {
			t.Fatal("wrong alg")
		}
	})
	t.Run("bad_token", func(t *testing.T) {
		_, err := v.VerifyJWT("bad")
		if err == nil {
			t.Fatal("expected error")
		}
	})
	t.Run("bad_sig", func(t *testing.T) {
		_, err := v.VerifyJWT(tok[:len(tok)-4] + "AAAA")
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

// ============================================================
// validate.go
// ============================================================

func TestCov_ValidationError(t *testing.T) {
	ve := &ValidationError{
		Code:        "token_expired",
		Description: "exp: expired 5m ago",
		Err:         ErrAfterExp,
	}
	if ve.Error() != "exp: expired 5m ago" {
		t.Fatalf("Error()=%q", ve.Error())
	}
	if ve.Unwrap() != ErrAfterExp {
		t.Fatal("Unwrap mismatch")
	}
	if !errors.Is(ve, ErrAfterExp) {
		t.Fatal("errors.Is should match ErrAfterExp")
	}
	// ErrAfterExp wraps ErrInvalidClaim
	if !errors.Is(ve, ErrInvalidClaim) {
		t.Fatal("errors.Is should match ErrInvalidClaim via chain")
	}
}

func TestCov_ValidationErrors(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if ves := ValidationErrors(nil); ves != nil {
			t.Fatal("expected nil")
		}
	})
	t.Run("joined_with_VEs", func(t *testing.T) {
		ve1 := &ValidationError{Code: "a", Err: ErrAfterExp}
		ve2 := &ValidationError{Code: "b", Err: ErrMissingClaim}
		joined := errors.Join(ve1, ve2)
		ves := ValidationErrors(joined)
		if len(ves) != 2 {
			t.Fatalf("expected 2, got %d", len(ves))
		}
	})
	t.Run("joined_no_VEs", func(t *testing.T) {
		joined := errors.Join(fmt.Errorf("plain error"))
		if ves := ValidationErrors(joined); ves != nil {
			t.Fatal("expected nil for no VEs")
		}
	})
	t.Run("single_VE", func(t *testing.T) {
		ve := &ValidationError{Code: "a", Err: ErrAfterExp}
		ves := ValidationErrors(ve)
		if len(ves) != 1 {
			t.Fatalf("expected 1, got %d", len(ves))
		}
	})
	t.Run("single_non_VE", func(t *testing.T) {
		if ves := ValidationErrors(fmt.Errorf("plain")); ves != nil {
			t.Fatal("expected nil")
		}
	})
}

func TestCov_GetOAuth2Error(t *testing.T) {
	t.Run("nil", func(t *testing.T) {
		if code := GetOAuth2Error(nil); code != "" {
			t.Fatalf("expected empty, got %q", code)
		}
	})
	t.Run("no_VEs", func(t *testing.T) {
		if code := GetOAuth2Error(fmt.Errorf("plain")); code != "" {
			t.Fatalf("expected empty, got %q", code)
		}
	})
	t.Run("invalid_token", func(t *testing.T) {
		ve := &ValidationError{Code: "token_expired", Err: ErrAfterExp}
		if code := GetOAuth2Error(ve); code != "invalid_token" {
			t.Fatalf("expected invalid_token, got %q", code)
		}
	})
	t.Run("insufficient_scope", func(t *testing.T) {
		ve := &ValidationError{Code: "insufficient_scope", Err: ErrInsufficientScope}
		if code := GetOAuth2Error(ve); code != "insufficient_scope" {
			t.Fatalf("expected insufficient_scope, got %q", code)
		}
	})
	t.Run("server_error", func(t *testing.T) {
		ve := &ValidationError{Code: "server_error", Err: ErrMisconfigured}
		if code := GetOAuth2Error(ve); code != "server_error" {
			t.Fatalf("expected server_error, got %q", code)
		}
	})
	t.Run("server_error_wins_over_scope", func(t *testing.T) {
		ve1 := &ValidationError{Err: ErrInsufficientScope}
		ve2 := &ValidationError{Err: ErrMisconfigured}
		joined := errors.Join(ve1, ve2)
		if code := GetOAuth2Error(joined); code != "server_error" {
			t.Fatalf("expected server_error, got %q", code)
		}
	})
}

func TestCov_codeFor(t *testing.T) {
	tests := []struct {
		sentinel error
		code     string
	}{
		{ErrAfterExp, "token_expired"},
		{ErrBeforeNBf, "token_not_yet_valid"},
		{ErrBeforeIAt, "future_issued_at"},
		{ErrBeforeAuthTime, "future_auth_time"},
		{ErrAfterAuthMaxAge, "auth_time_exceeded"},
		{ErrInsufficientScope, "insufficient_scope"},
		{ErrMissingClaim, "missing_claim"},
		{ErrInvalidTyp, "invalid_typ"},
		{ErrInvalidClaim, "invalid_claim"},
		{ErrMisconfigured, "server_error"},
		{fmt.Errorf("unknown"), "unknown_error"},
	}
	for _, tt := range tests {
		got := codeFor(tt.sentinel)
		if got != tt.code {
			t.Errorf("codeFor(%v)=%q want %q", tt.sentinel, got, tt.code)
		}
	}
}

func TestCov_isTimeSentinel(t *testing.T) {
	for _, s := range []error{ErrAfterExp, ErrBeforeNBf, ErrBeforeIAt, ErrBeforeAuthTime, ErrAfterAuthMaxAge} {
		if !isTimeSentinel(s) {
			t.Errorf("expected isTimeSentinel(%v)=true", s)
		}
	}
	for _, s := range []error{ErrMissingClaim, ErrInvalidClaim, ErrMisconfigured, ErrInsufficientScope} {
		if isTimeSentinel(s) {
			t.Errorf("expected isTimeSentinel(%v)=false", s)
		}
	}
}

func TestCov_formatDuration(t *testing.T) {
	t.Run("full", func(t *testing.T) {
		d := 25*time.Hour + 30*time.Minute + 45*time.Second
		got := formatDuration(d)
		if got != "1d 1h 30m 45s" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("sub_second", func(t *testing.T) {
		got := formatDuration(500 * time.Millisecond)
		if got != "500ms" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("zero", func(t *testing.T) {
		got := formatDuration(0)
		if got != "0ms" {
			t.Fatalf("got %q", got)
		}
	})
	t.Run("negative", func(t *testing.T) {
		got := formatDuration(-5 * time.Second)
		if got != "5s" {
			t.Fatalf("got %q", got)
		}
	})
}

func TestCov_resolveSkew(t *testing.T) {
	if got := resolveSkew(0); got != defaultGracePeriod {
		t.Fatalf("zero: got %v want %v", got, defaultGracePeriod)
	}
	if got := resolveSkew(-1); got != 0 {
		t.Fatalf("negative: got %v want 0", got)
	}
	if got := resolveSkew(5 * time.Second); got != 5*time.Second {
		t.Fatalf("positive: got %v want 5s", got)
	}
}

func TestCov_NewIDTokenValidator(t *testing.T) {
	v := NewIDTokenValidator([]string{"iss"}, []string{"aud"}, []string{"azp"})
	if v.Checks&ChecksConfigured == 0 {
		t.Fatal("expected ChecksConfigured")
	}
	if v.Checks&CheckIss == 0 || v.Checks&CheckAud == 0 {
		t.Fatal("expected CheckIss and CheckAud when slices provided")
	}
	if v.Checks&CheckSub == 0 || v.Checks&CheckExp == 0 {
		t.Fatal("expected CheckSub and CheckExp")
	}

	// nil iss/aud should not set those check bits
	v2 := NewIDTokenValidator(nil, nil, nil)
	if v2.Checks&CheckIss != 0 {
		t.Fatal("expected no CheckIss for nil iss")
	}
	if v2.Checks&CheckAud != 0 {
		t.Fatal("expected no CheckAud for nil aud")
	}
}

func TestCov_NewAccessTokenValidator(t *testing.T) {
	v := NewAccessTokenValidator([]string{"iss"}, []string{"aud"})
	if v.Checks&ChecksConfigured == 0 {
		t.Fatal("expected ChecksConfigured")
	}
	if v.Checks&CheckJTI == 0 || v.Checks&CheckClientID == 0 {
		t.Fatal("expected CheckJTI and CheckClientID for access token")
	}

	v2 := NewAccessTokenValidator(nil, nil)
	if v2.Checks&CheckIss != 0 {
		t.Fatal("expected no CheckIss for nil iss")
	}
}

func TestCov_NewAccessTokenValidator_Scopes(t *testing.T) {
	iss := []string{"https://example.com"}
	aud := []string{"https://api.example.com"}

	t.Run("nil_no_scope_check", func(t *testing.T) {
		// No scope args: CheckScope not set, scope claim not validated.
		v := NewAccessTokenValidator(iss, aud)
		if v.Checks&CheckScope != 0 {
			t.Fatal("expected CheckScope not set for nil scopes")
		}
		if v.RequiredScopes != nil {
			t.Fatal("expected nil RequiredScopes")
		}
		// Validate passes even with no scope claim.
		claims := goodClaims()
		claims.Scope = nil
		claims.JTI = "jti-x"
		if err := v.Validate(nil, claims, testNow); err != nil {
			t.Fatalf("expected no error without scope check, got %v", err)
		}
	})

	t.Run("empty_presence_only", func(t *testing.T) {
		// Empty spread: CheckScope set, any non-empty scope accepted.
		v := NewAccessTokenValidator(iss, aud, []string{}...)
		if v.Checks&CheckScope == 0 {
			t.Fatal("expected CheckScope set for empty non-nil scopes")
		}
		if v.RequiredScopes == nil {
			t.Fatal("expected non-nil RequiredScopes")
		}
		// Validate passes when scope is present.
		if err := v.Validate(nil, goodClaims(), testNow); err != nil {
			t.Fatalf("expected no error with scope present, got %v", err)
		}
		// Validate fails when scope is absent.
		claims := goodClaims()
		claims.Scope = nil
		err := v.Validate(nil, claims, testNow)
		if !errors.Is(err, ErrMissingClaim) {
			t.Fatalf("expected ErrMissingClaim for absent scope, got %v", err)
		}
	})

	t.Run("specific_scope", func(t *testing.T) {
		// Specific scope: CheckScope set, token must contain "openid".
		v := NewAccessTokenValidator(iss, aud, "openid")
		if v.Checks&CheckScope == 0 {
			t.Fatal("expected CheckScope set")
		}
		// Validate passes when scope contains "openid".
		if err := v.Validate(nil, goodClaims(), testNow); err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		// Validate fails when "openid" is absent from scope.
		claims := goodClaims()
		claims.Scope = SpaceDelimited{"profile"}
		err := v.Validate(nil, claims, testNow)
		if !errors.Is(err, ErrInsufficientScope) {
			t.Fatalf("expected ErrInsufficientScope, got %v", err)
		}
	})
}

func TestCov_Validate_Unconfigured(t *testing.T) {
	v := &Validator{} // zero value
	err := v.Validate(nil, goodClaims(), testNow)
	if !errors.Is(err, ErrMisconfigured) {
		t.Fatalf("expected ErrMisconfigured, got %v", err)
	}
}

func TestCov_Validate_AllPass(t *testing.T) {
	v := NewIDTokenValidator([]string{"https://example.com"}, []string{"https://api.example.com"}, []string{"client-abc"})
	err := v.Validate(nil, goodClaims(), testNow)
	if err != nil {
		t.Fatalf("expected nil, got %v", err)
	}
}

func TestCov_Validate_TimeAnnotation(t *testing.T) {
	v := NewIDTokenValidator([]string{"https://example.com"}, []string{"https://api.example.com"}, nil)
	claims := goodClaims()
	claims.Exp = testNow.Add(-time.Hour).Unix() // expired
	err := v.Validate(nil, claims, testNow)
	if err == nil {
		t.Fatal("expected error")
	}
	// Time errors get annotated with "server time"
	if !strings.Contains(err.Error(), "server time") {
		t.Fatalf("expected server time annotation, got: %s", err.Error())
	}
}

func TestCov_Validate_ExplicitConfigForcesChecks(t *testing.T) {
	// Even without Check flags, non-empty Iss forces iss check
	v := &Validator{
		Checks: ChecksConfigured,
		Iss:    []string{"https://other.com"},
	}
	claims := goodClaims()
	err := v.Validate(nil, claims, testNow)
	if !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("expected ErrInvalidClaim from forced iss check, got %v", err)
	}
}

func TestCov_Validate_AllChecks(t *testing.T) {
	// Enable every check via the bitmask
	v := &Validator{
		Checks: ChecksConfigured | CheckIss | CheckSub | CheckAud | CheckExp |
			CheckNBf | CheckIAt | CheckJTI | CheckClientID | CheckAuthTime |
			CheckAzP | CheckScope,
		Iss:            []string{"https://example.com"},
		Aud:            []string{"https://api.example.com"},
		AzP:            []string{"client-abc"},
		RequiredScopes: []string{"openid"},
	}
	claims := goodClaims()
	claims.NBf = testNow.Add(-time.Minute).Unix()
	err := v.Validate(nil, claims, testNow)
	if err != nil {
		t.Fatalf("expected all pass, got %v", err)
	}
}

func TestCov_Validate_PreExistingErrors(t *testing.T) {
	v := NewIDTokenValidator([]string{"https://example.com"}, []string{"https://api.example.com"}, nil)
	prior := []error{&ValidationError{Code: "invalid_claim", Description: "typ wrong", Err: ErrInvalidClaim}}
	err := v.Validate(prior, goodClaims(), testNow)
	// Should include the prior error in the joined result
	if err == nil {
		t.Fatal("expected error from prior errors")
	}
	if !strings.Contains(err.Error(), "typ wrong") {
		t.Fatalf("expected prior error in result, got: %s", err.Error())
	}
}

func TestCov_Validate_ExplicitAud(t *testing.T) {
	// Non-empty Aud forces CheckAud even without the flag
	v := &Validator{
		Checks: ChecksConfigured,
		Aud:    []string{"wrong-aud"},
	}
	err := v.Validate(nil, goodClaims(), testNow)
	if !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("expected ErrInvalidClaim, got %v", err)
	}
}

func TestCov_Validate_ExplicitAzP(t *testing.T) {
	// Non-empty AzP forces CheckAzP
	v := &Validator{
		Checks: ChecksConfigured,
		AzP:    []string{"wrong-azp"},
	}
	err := v.Validate(nil, goodClaims(), testNow)
	if !errors.Is(err, ErrInvalidClaim) {
		t.Fatalf("expected ErrInvalidClaim, got %v", err)
	}
}

func TestCov_Validate_ExplicitScopes(t *testing.T) {
	// Non-empty RequiredScopes forces CheckScope
	v := &Validator{
		Checks:         ChecksConfigured,
		RequiredScopes: []string{"admin"},
	}
	err := v.Validate(nil, goodClaims(), testNow)
	if !errors.Is(err, ErrInsufficientScope) {
		t.Fatalf("expected ErrInsufficientScope, got %v", err)
	}
}

func TestCov_Validate_ExplicitMaxAge(t *testing.T) {
	// MaxAge > 0 forces auth_time check
	v := &Validator{
		Checks: ChecksConfigured,
		MaxAge: 1 * time.Second, // very short
	}
	err := v.Validate(nil, goodClaims(), testNow)
	if !errors.Is(err, ErrAfterAuthMaxAge) {
		t.Fatalf("expected ErrAfterAuthMaxAge, got %v", err)
	}
}

func TestCov_Validate_ErrorsIsChain(t *testing.T) {
	// Verify that errors.Is works through the full Validate path:
	// the returned error should match both ErrAfterExp and ErrInvalidClaim.
	v := NewIDTokenValidator([]string{"https://example.com"}, []string{"https://api.example.com"}, nil)
	claims := goodClaims()
	claims.Exp = testNow.Add(-time.Hour).Unix() // expired
	err := v.Validate(nil, claims, testNow)
	if err == nil {
		t.Fatal("expected error")
	}
	if !errors.Is(err, ErrAfterExp) {
		t.Fatal("expected errors.Is(err, ErrAfterExp)")
	}
	if !errors.Is(err, ErrInvalidClaim) {
		t.Fatal("expected errors.Is(err, ErrInvalidClaim) via chain")
	}
}

func TestCov_Validate_NegativeGracePeriod(t *testing.T) {
	// Negative GracePeriod disables skew tolerance entirely.
	// A token that expired 1s ago should fail even though default skew is 2s.
	v := &Validator{
		Checks:      ChecksConfigured | CheckExp,
		GracePeriod: -1,
	}
	claims := goodClaims()
	claims.Exp = testNow.Add(-1 * time.Second).Unix()
	err := v.Validate(nil, claims, testNow)
	if !errors.Is(err, ErrAfterExp) {
		t.Fatalf("expected ErrAfterExp with no skew, got %v", err)
	}
}

func TestCov_Validate_EmptyIss_Misconfigured(t *testing.T) {
	// Non-nil empty Iss forces the check and returns misconfigured.
	v := &Validator{
		Checks: ChecksConfigured,
		Iss:    []string{},
	}
	err := v.Validate(nil, goodClaims(), testNow)
	if !errors.Is(err, ErrMisconfigured) {
		t.Fatalf("expected ErrMisconfigured for empty Iss, got %v", err)
	}
}

func TestCov_Validate_EmptyAud_Misconfigured(t *testing.T) {
	// Non-nil empty Aud forces the check and returns misconfigured.
	v := &Validator{
		Checks: ChecksConfigured,
		Aud:    []string{},
	}
	err := v.Validate(nil, goodClaims(), testNow)
	if !errors.Is(err, ErrMisconfigured) {
		t.Fatalf("expected ErrMisconfigured for empty Aud, got %v", err)
	}
}

func TestCov_Verify_PrefersSigInvalid(t *testing.T) {
	// When multiple keys are tried, ErrSignatureInvalid should be preferred
	// over ErrAlgConflict. Verifier has an RSA key (wrong type) and an
	// Ed25519 key (right type, wrong material).
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	tok := mustSignStr(t, s, goodClaims())
	jws, _ := Decode(tok)
	kid := jws.GetHeader().KID

	// RSA key will give ErrAlgConflict; wrong Ed25519 gives ErrSignatureInvalid
	rsaPub, _ := FromPublicKey(&mustRSAKey(t).PublicKey)
	rsaPub.KID = kid
	edPub, _ := FromPublicKey(mustEdKey(t).Public())
	edPub.KID = kid

	v, _ := NewVerifier([]PublicKey{*rsaPub, *edPub})
	err := v.Verify(jws)
	if !errors.Is(err, ErrSignatureInvalid) {
		t.Fatalf("expected ErrSignatureInvalid (preferred over ErrAlgConflict), got %v", err)
	}
}

// --- Per-claim check methods ---

func TestCov_IsAllowedIss(t *testing.T) {
	tc := goodClaims()

	t.Run("nil_allowed", func(t *testing.T) {
		errs := tc.IsAllowedIss(nil, nil)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMisconfigured) {
			t.Fatal("expected ErrMisconfigured for nil")
		}
	})
	t.Run("empty_allowed", func(t *testing.T) {
		errs := tc.IsAllowedIss(nil, []string{})
		if len(errs) != 1 || !errors.Is(errs[0], ErrMisconfigured) {
			t.Fatal("expected ErrMisconfigured for empty")
		}
	})
	t.Run("missing_iss", func(t *testing.T) {
		tc2 := &TokenClaims{}
		errs := tc2.IsAllowedIss(nil, []string{"x"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("not_in_list", func(t *testing.T) {
		errs := tc.IsAllowedIss(nil, []string{"https://other.com"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrInvalidClaim) {
			t.Fatal("expected ErrInvalidClaim")
		}
	})
	t.Run("wildcard", func(t *testing.T) {
		errs := tc.IsAllowedIss(nil, []string{"*"})
		if len(errs) != 0 {
			t.Fatal("expected pass with wildcard")
		}
	})
	t.Run("match", func(t *testing.T) {
		errs := tc.IsAllowedIss(nil, []string{"https://example.com"})
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
}

func TestCov_IsPresentSub(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		tc := &TokenClaims{}
		errs := tc.IsPresentSub(nil)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("present", func(t *testing.T) {
		errs := goodClaims().IsPresentSub(nil)
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
}

func TestCov_HasAllowedAud(t *testing.T) {
	tc := goodClaims()

	t.Run("nil_allowed", func(t *testing.T) {
		errs := tc.HasAllowedAud(nil, nil)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMisconfigured) {
			t.Fatal("expected ErrMisconfigured for nil")
		}
	})
	t.Run("empty_allowed", func(t *testing.T) {
		errs := tc.HasAllowedAud(nil, []string{})
		if len(errs) != 1 || !errors.Is(errs[0], ErrMisconfigured) {
			t.Fatal("expected ErrMisconfigured for empty")
		}
	})
	t.Run("missing_aud", func(t *testing.T) {
		tc2 := &TokenClaims{}
		errs := tc2.HasAllowedAud(nil, []string{"x"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("not_in_list", func(t *testing.T) {
		errs := tc.HasAllowedAud(nil, []string{"wrong"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrInvalidClaim) {
			t.Fatal("expected ErrInvalidClaim")
		}
	})
	t.Run("wildcard", func(t *testing.T) {
		errs := tc.HasAllowedAud(nil, []string{"*"})
		if len(errs) != 0 {
			t.Fatal("expected pass with wildcard")
		}
	})
	t.Run("intersects", func(t *testing.T) {
		errs := tc.HasAllowedAud(nil, []string{"https://api.example.com"})
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
}

func TestCov_IsBeforeExp(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		tc := &TokenClaims{}
		errs := tc.IsBeforeExp(nil, testNow, 0)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("expired", func(t *testing.T) {
		tc := goodClaims()
		tc.Exp = testNow.Add(-time.Hour).Unix()
		errs := tc.IsBeforeExp(nil, testNow, 0)
		if len(errs) != 1 || !errors.Is(errs[0], ErrAfterExp) {
			t.Fatal("expected ErrAfterExp")
		}
	})
	t.Run("valid", func(t *testing.T) {
		errs := goodClaims().IsBeforeExp(nil, testNow, 0)
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
	t.Run("within_skew", func(t *testing.T) {
		tc := goodClaims()
		tc.Exp = testNow.Add(-1 * time.Second).Unix()
		errs := tc.IsBeforeExp(nil, testNow, 2*time.Second)
		if len(errs) != 0 {
			t.Fatal("expected pass within skew")
		}
	})
}

func TestCov_IsAfterNBf(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		tc := &TokenClaims{}
		errs := tc.IsAfterNBf(nil, testNow, 0)
		if len(errs) != 0 {
			t.Fatal("expected pass for absent nbf")
		}
	})
	t.Run("future", func(t *testing.T) {
		tc := &TokenClaims{NBf: testNow.Add(time.Hour).Unix()}
		errs := tc.IsAfterNBf(nil, testNow, 0)
		if len(errs) != 1 || !errors.Is(errs[0], ErrBeforeNBf) {
			t.Fatal("expected ErrBeforeNBf")
		}
	})
	t.Run("valid", func(t *testing.T) {
		tc := &TokenClaims{NBf: testNow.Add(-time.Minute).Unix()}
		errs := tc.IsAfterNBf(nil, testNow, 0)
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
	t.Run("within_skew", func(t *testing.T) {
		// nbf is 1s in the future, but skew of 2s accepts it
		tc := &TokenClaims{NBf: testNow.Add(1 * time.Second).Unix()}
		errs := tc.IsAfterNBf(nil, testNow, 2*time.Second)
		if len(errs) != 0 {
			t.Fatal("expected pass within skew")
		}
	})
}

func TestCov_IsAfterIAt(t *testing.T) {
	t.Run("absent", func(t *testing.T) {
		tc := &TokenClaims{}
		errs := tc.IsAfterIAt(nil, testNow, 0)
		if len(errs) != 0 {
			t.Fatal("expected pass for absent iat")
		}
	})
	t.Run("future", func(t *testing.T) {
		tc := &TokenClaims{IAt: testNow.Add(time.Hour).Unix()}
		errs := tc.IsAfterIAt(nil, testNow, 0)
		if len(errs) != 1 || !errors.Is(errs[0], ErrBeforeIAt) {
			t.Fatal("expected ErrBeforeIAt")
		}
	})
	t.Run("valid", func(t *testing.T) {
		tc := goodClaims()
		errs := tc.IsAfterIAt(nil, testNow, 0)
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
	t.Run("within_skew", func(t *testing.T) {
		// iat is 1s in the future, but skew of 2s accepts it
		tc := &TokenClaims{IAt: testNow.Add(1 * time.Second).Unix()}
		errs := tc.IsAfterIAt(nil, testNow, 2*time.Second)
		if len(errs) != 0 {
			t.Fatal("expected pass within skew")
		}
	})
}

func TestCov_IsPresentJTI(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		tc := &TokenClaims{}
		errs := tc.IsPresentJTI(nil)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("present", func(t *testing.T) {
		errs := goodClaims().IsPresentJTI(nil)
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
}

func TestCov_IsValidAuthTime(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		tc := &TokenClaims{}
		errs := tc.IsValidAuthTime(nil, testNow, 0, 0)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("future", func(t *testing.T) {
		tc := &TokenClaims{AuthTime: testNow.Add(time.Hour).Unix()}
		errs := tc.IsValidAuthTime(nil, testNow, 0, 0)
		if len(errs) != 1 || !errors.Is(errs[0], ErrBeforeAuthTime) {
			t.Fatal("expected ErrBeforeAuthTime")
		}
	})
	t.Run("maxAge_exceeded", func(t *testing.T) {
		tc := &TokenClaims{AuthTime: testNow.Add(-time.Hour).Unix()}
		errs := tc.IsValidAuthTime(nil, testNow, 0, 30*time.Minute)
		if len(errs) != 1 || !errors.Is(errs[0], ErrAfterAuthMaxAge) {
			t.Fatal("expected ErrAfterAuthMaxAge")
		}
	})
	t.Run("valid_with_maxAge", func(t *testing.T) {
		tc := goodClaims() // auth_time is 5m ago
		errs := tc.IsValidAuthTime(nil, testNow, 0, time.Hour)
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
	t.Run("valid_without_maxAge", func(t *testing.T) {
		tc := goodClaims()
		errs := tc.IsValidAuthTime(nil, testNow, 0, 0)
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
	t.Run("future_within_skew", func(t *testing.T) {
		// auth_time is 1s in the future, but skew of 2s accepts it
		tc := &TokenClaims{AuthTime: testNow.Add(1 * time.Second).Unix()}
		errs := tc.IsValidAuthTime(nil, testNow, 2*time.Second, 0)
		if len(errs) != 0 {
			t.Fatal("expected pass within skew")
		}
	})
	t.Run("maxAge_within_skew", func(t *testing.T) {
		// auth_time is 31m ago, maxAge is 30m, but skew of 2m accepts it
		tc := &TokenClaims{AuthTime: testNow.Add(-31 * time.Minute).Unix()}
		errs := tc.IsValidAuthTime(nil, testNow, 2*time.Minute, 30*time.Minute)
		if len(errs) != 0 {
			t.Fatal("expected pass: maxAge exceeded by 1m but within 2m skew")
		}
	})
}

func TestCov_IsAllowedAzP(t *testing.T) {
	tc := goodClaims()

	t.Run("nil_allowed", func(t *testing.T) {
		errs := tc.IsAllowedAzP(nil, nil)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMisconfigured) {
			t.Fatal("expected ErrMisconfigured")
		}
	})
	t.Run("empty_allowed", func(t *testing.T) {
		errs := tc.IsAllowedAzP(nil, []string{})
		if len(errs) != 1 || !errors.Is(errs[0], ErrMisconfigured) {
			t.Fatal("expected ErrMisconfigured")
		}
	})
	t.Run("missing", func(t *testing.T) {
		tc2 := &TokenClaims{}
		errs := tc2.IsAllowedAzP(nil, []string{"x"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("not_in_list", func(t *testing.T) {
		errs := tc.IsAllowedAzP(nil, []string{"wrong"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrInvalidClaim) {
			t.Fatal("expected ErrInvalidClaim")
		}
	})
	t.Run("wildcard", func(t *testing.T) {
		errs := tc.IsAllowedAzP(nil, []string{"*"})
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
	t.Run("match", func(t *testing.T) {
		errs := tc.IsAllowedAzP(nil, []string{"client-abc"})
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
}

func TestCov_IsPresentClientID(t *testing.T) {
	t.Run("missing", func(t *testing.T) {
		tc := &TokenClaims{}
		errs := tc.IsPresentClientID(nil)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("present", func(t *testing.T) {
		errs := goodClaims().IsPresentClientID(nil)
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
}

func TestCov_ContainsScopes(t *testing.T) {
	t.Run("missing_scope", func(t *testing.T) {
		tc := &TokenClaims{}
		errs := tc.ContainsScopes(nil, nil)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMissingClaim) {
			t.Fatal("expected ErrMissingClaim")
		}
	})
	t.Run("missing_required", func(t *testing.T) {
		tc := goodClaims()
		errs := tc.ContainsScopes(nil, []string{"admin"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrInsufficientScope) {
			t.Fatal("expected ErrInsufficientScope")
		}
	})
	t.Run("all_present", func(t *testing.T) {
		tc := goodClaims()
		errs := tc.ContainsScopes(nil, []string{"openid"})
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
	t.Run("presence_only", func(t *testing.T) {
		tc := goodClaims()
		errs := tc.ContainsScopes(nil, nil)
		if len(errs) != 0 {
			t.Fatal("expected pass for presence-only")
		}
	})
}

func TestCov_IsAllowedTyp(t *testing.T) {
	t.Run("empty_allowed", func(t *testing.T) {
		h := &RFCHeader{Typ: "JWT"}
		errs := h.IsAllowedTyp(nil, nil)
		if len(errs) != 1 || !errors.Is(errs[0], ErrMisconfigured) {
			t.Fatal("expected ErrMisconfigured")
		}
	})
	t.Run("not_in_list", func(t *testing.T) {
		h := &RFCHeader{Typ: "at+jwt"}
		errs := h.IsAllowedTyp(nil, []string{"JWT"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrInvalidTyp) {
			t.Fatal("expected ErrInvalidTyp")
		}
	})
	t.Run("case_insensitive_match", func(t *testing.T) {
		h := &RFCHeader{Typ: "jwt"}
		errs := h.IsAllowedTyp(nil, []string{"JWT"})
		if len(errs) != 0 {
			t.Fatal("expected pass (case-insensitive)")
		}
	})
	t.Run("exact_match", func(t *testing.T) {
		h := &RFCHeader{Typ: "JWT"}
		errs := h.IsAllowedTyp(nil, []string{"JWT"})
		if len(errs) != 0 {
			t.Fatal("expected pass")
		}
	})
	t.Run("empty_typ_not_in_list", func(t *testing.T) {
		h := &RFCHeader{}
		errs := h.IsAllowedTyp(nil, []string{"JWT"})
		if len(errs) != 1 || !errors.Is(errs[0], ErrInvalidTyp) {
			t.Fatal("expected ErrInvalidTyp for empty typ")
		}
	})
}

// ============================================================
// Additional coverage: parse helpers, marshal, NewPrivateKey, etc.
// ============================================================

func TestCov_NewAccessToken_BadClaims(t *testing.T) {
	_, err := NewAccessToken(&badClaims{Bad: make(chan int)})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCov_ParsePublicJWK(t *testing.T) {
	// Create a valid JWK JSON via marshal round-trip
	pub, _ := FromPublicKey(mustEdKey(t).Public())
	data, _ := json.Marshal(pub)

	pk, err := ParsePublicJWK(data)
	if err != nil {
		t.Fatal(err)
	}
	if pk.KID == "" {
		t.Fatal("expected KID")
	}

	// Bad JSON
	_, err = ParsePublicJWK([]byte("{bad"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCov_ParsePrivateJWK(t *testing.T) {
	edKey := mustEdKey(t)
	pk := mustFromPrivate(t, edKey)
	// Need to give it a KID so NewSigner doesn't complain
	s := mustSigner(t, pk)
	_ = s // just to exercise key

	// Marshal the private key
	data, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := ParsePrivateJWK(data)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KID == "" {
		t.Fatal("expected KID")
	}

	// Bad JSON
	_, err = ParsePrivateJWK([]byte("{bad"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCov_ParseWellKnownJWKs(t *testing.T) {
	pub, _ := FromPublicKey(mustEdKey(t).Public())
	jwks := WellKnownJWKs{Keys: []PublicKey{*pub}}
	data, _ := json.Marshal(jwks)

	parsed, err := ParseWellKnownJWKs(data)
	if err != nil {
		t.Fatal(err)
	}
	if len(parsed.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(parsed.Keys))
	}

	// Bad JSON
	_, err = ParseWellKnownJWKs([]byte("{bad"))
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestCov_PublicKey_MarshalJSON(t *testing.T) {
	pub, _ := FromPublicKey(mustEdKey(t).Public())
	data, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected data")
	}

	// Error path: unsupported key
	bad := PublicKey{Key: fakeKey{}}
	_, err = json.Marshal(bad)
	if err == nil {
		t.Fatal("expected error for unsupported key")
	}
}

func TestCov_PrivateKey_MarshalJSON(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	data, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}
	if len(data) == 0 {
		t.Fatal("expected data")
	}
}

func TestCov_PublicKey_Thumbprint_AllTypes(t *testing.T) {
	// EC
	ecPub, _ := FromPublicKey(&mustECKey(t, elliptic.P256()).PublicKey)
	if _, err := ecPub.Thumbprint(); err != nil {
		t.Fatal(err)
	}

	// RSA
	rsaPub, _ := FromPublicKey(&mustRSAKey(t).PublicKey)
	if _, err := rsaPub.Thumbprint(); err != nil {
		t.Fatal(err)
	}

	// OKP (Ed25519)
	edPub, _ := FromPublicKey(mustEdKey(t).Public())
	if _, err := edPub.Thumbprint(); err != nil {
		t.Fatal(err)
	}
}

func TestCov_Sign_BadClaims(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	_, err := s.Sign(&badClaims{Bad: make(chan int)})
	if err == nil {
		t.Fatal("expected error for bad claims")
	}
}

func TestCov_SignToString_BadClaims(t *testing.T) {
	pk := mustFromPrivate(t, mustEdKey(t))
	s := mustSigner(t, pk)
	_, err := s.SignToString(&badClaims{Bad: make(chan int)})
	if err == nil {
		t.Fatal("expected error for bad claims")
	}
}

func TestCov_SignRaw_NilPrivKey(t *testing.T) {
	bad := &Signer{keys: []PrivateKey{{KID: "test"}}}
	_, err := bad.SignRaw(&RFCHeader{}, nil)
	if !errors.Is(err, ErrNoSigningKey) {
		t.Fatalf("expected ErrNoSigningKey, got %v", err)
	}
}

func TestCov_SetHeader_OK(t *testing.T) {
	jws, _ := New(goodClaims())
	hdr := jws.GetHeader()
	err := jws.SetHeader(&hdr)
	if err != nil {
		t.Fatal(err)
	}
}

func TestCov_FromPublicKey_Unsupported(t *testing.T) {
	_, err := FromPublicKey(fakeKey{})
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
	}
}

func TestCov_FromPublicKey_AllTypes(t *testing.T) {
	// EC
	pk, err := FromPublicKey(&mustECKey(t, elliptic.P384()).PublicKey)
	if err != nil || pk.Alg != "ES384" {
		t.Fatalf("EC: err=%v alg=%q", err, pk.Alg)
	}
	// RSA
	pk, err = FromPublicKey(&mustRSAKey(t).PublicKey)
	if err != nil || pk.Alg != "RS256" {
		t.Fatalf("RSA: err=%v alg=%q", err, pk.Alg)
	}
}

func TestCov_validateSigningKey_AllTypes(t *testing.T) {
	for _, tc := range []struct {
		name   string
		signer crypto.Signer
	}{
		{"EC", mustECKey(t, elliptic.P256())},
		{"RSA", mustRSAKey(t)},
		{"Ed25519", mustEdKey(t)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pk := mustFromPrivate(t, tc.signer)
			pub, err := pk.PublicKey()
			if err != nil {
				t.Fatal(err)
			}
			if err := validateSigningKey(pk, pub); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestCov_encode_AllTypes(t *testing.T) {
	// EC P-384
	ecPub, _ := FromPublicKey(&mustECKey(t, elliptic.P384()).PublicKey)
	if _, err := encode(*ecPub); err != nil {
		t.Fatal(err)
	}
	// EC P-521
	ecPub2, _ := FromPublicKey(&mustECKey(t, elliptic.P521()).PublicKey)
	if _, err := encode(*ecPub2); err != nil {
		t.Fatal(err)
	}
	// RSA
	rsaPub, _ := FromPublicKey(&mustRSAKey(t).PublicKey)
	if _, err := encode(*rsaPub); err != nil {
		t.Fatal(err)
	}
}

func TestCov_encodePrivate_AllTypes(t *testing.T) {
	// EC
	ecKey := mustECKey(t, elliptic.P256())
	ecPK := mustFromPrivate(t, ecKey)
	if _, err := encodePrivate(*ecPK); err != nil {
		t.Fatal(err)
	}
	// RSA
	rsaPK := mustFromPrivate(t, mustRSAKey(t))
	if _, err := encodePrivate(*rsaPK); err != nil {
		t.Fatal(err)
	}
}

func TestCov_decodeOne_RSA(t *testing.T) {
	rsaKey := mustRSAKey(t)
	pub, _ := FromPublicKey(&rsaKey.PublicKey)
	data, _ := json.Marshal(pub)
	var rk rawKey
	json.Unmarshal(data, &rk)
	pk, err := decodeOne(rk)
	if err != nil {
		t.Fatal(err)
	}
	if pk.Key == nil {
		t.Fatal("expected key")
	}
}

func TestCov_decodeOne_UnknownKty(t *testing.T) {
	_, err := decodeOne(rawKey{Kty: "UNKNOWN"})
	if !errors.Is(err, ErrUnsupportedKeyType) {
		t.Fatalf("expected ErrUnsupportedKeyType, got %v", err)
	}
}

func TestCov_decodePrivate_RSA(t *testing.T) {
	rsaKey := mustRSAKey(t)
	pk := mustFromPrivate(t, rsaKey)
	data, _ := json.Marshal(pk)
	var rk rawKey
	json.Unmarshal(data, &rk)
	priv, err := decodePrivate(rk)
	if err != nil {
		t.Fatal(err)
	}
	if priv.privKey == nil {
		t.Fatal("expected private key")
	}
}

func TestCov_decodePrivate_EC(t *testing.T) {
	ecKey := mustECKey(t, elliptic.P256())
	pk := mustFromPrivate(t, ecKey)
	data, _ := json.Marshal(pk)
	var rk rawKey
	json.Unmarshal(data, &rk)
	priv, err := decodePrivate(rk)
	if err != nil {
		t.Fatal(err)
	}
	if priv.privKey == nil {
		t.Fatal("expected private key")
	}
}

func TestCov_signingParams_RSA(t *testing.T) {
	rsaKey := mustRSAKey(t)
	alg, hash, ecKeySize, err := signingParams(rsaKey)
	if err != nil || alg != "RS256" || hash == 0 || ecKeySize != 0 {
		t.Fatalf("unexpected: alg=%q hash=%v ecKeySize=%d err=%v", alg, hash, ecKeySize, err)
	}
}

func TestCov_signBytes_RSA(t *testing.T) {
	rsaKey := mustRSAKey(t)
	sig, err := signBytes(rsaKey, "RS256", crypto.SHA256, 0, []byte("test input"))
	if err != nil || len(sig) == 0 {
		t.Fatal(err)
	}
}

func TestCov_verifyOneKey_EC_CurveMismatch(t *testing.T) {
	// ES256 key but token says ES384
	h := RFCHeader{Alg: "ES384", KID: "k"}
	err := verifyOneKey(h, &mustECKey(t, elliptic.P256()).PublicKey, []byte("input"), make([]byte, 96))
	if !errors.Is(err, ErrAlgConflict) {
		t.Fatalf("expected ErrAlgConflict, got %v", err)
	}
}
