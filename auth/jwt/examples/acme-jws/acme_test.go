package main

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/therootcompany/golib/auth/jwt"
)

// TestNewAccountJWS verifies ACME newAccount signing: jwk in header,
// kid absent, typ absent, payload is newAccount body.
func TestNewAccountJWS(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	pubKey, err := pk.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	jwkBytes, err := json.Marshal(pubKey)
	if err != nil {
		t.Fatal(err)
	}

	payload := NewAccountPayload{
		TermsOfServiceAgreed: true,
		Contact:              []string{"mailto:cert-admin@example.com"},
	}
	payloadJSON, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}

	hdr := &AcmeHeader{
		URL:   "https://acme.example.com/acme/new-account",
		Nonce: "abc123-server-nonce",
		JWK:   json.RawMessage(jwkBytes),
		// KID is empty for newAccount -- jwk is used instead.
	}

	raw, err := signer.SignRaw(hdr, payloadJSON)
	if err != nil {
		t.Fatal(err)
	}

	// Verify protected header has ACME fields and no typ.
	headerJSON, err := base64.RawURLEncoding.DecodeString(string(raw.Protected))
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(headerJSON, &decoded); err != nil {
		t.Fatal(err)
	}

	if _, ok := decoded["typ"]; ok {
		t.Error("ACME header must not contain typ")
	}
	if decoded["alg"] != "EdDSA" {
		t.Errorf("alg = %v, want EdDSA", decoded["alg"])
	}
	if decoded["url"] != "https://acme.example.com/acme/new-account" {
		t.Errorf("url = %v", decoded["url"])
	}
	if decoded["nonce"] != "abc123-server-nonce" {
		t.Errorf("nonce = %v", decoded["nonce"])
	}
	if decoded["jwk"] == nil {
		t.Error("newAccount header must contain jwk")
	}
	if _, ok := decoded["kid"]; ok {
		t.Error("newAccount header must not contain kid (mutually exclusive with jwk)")
	}

	// Verify signature is present.
	if len(raw.Signature) == 0 {
		t.Fatal("signature is empty")
	}

	// Verify RawJWT marshals as flattened JWS JSON.
	flat, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var flatMap map[string]string
	if err := json.Unmarshal(flat, &flatMap); err != nil {
		t.Fatalf("flattened JWS is not valid JSON: %v", err)
	}
	for _, field := range []string{"protected", "payload", "signature"} {
		if flatMap[field] == "" {
			t.Errorf("flattened JWS missing %q field", field)
		}
	}

	// Round-trip: unmarshal flattened JWS back into a RawJWT.
	var roundTrip jwt.RawJWT
	if err := json.Unmarshal(flat, &roundTrip); err != nil {
		t.Fatalf("unmarshal flattened JWS: %v", err)
	}
	if string(roundTrip.Protected) != string(raw.Protected) {
		t.Error("round-trip: protected mismatch")
	}
	if string(roundTrip.Payload) != string(raw.Payload) {
		t.Error("round-trip: payload mismatch")
	}
	if string(roundTrip.Signature) != string(raw.Signature) {
		t.Error("round-trip: signature mismatch")
	}
}

// TestAuthenticatedRequestJWS verifies ACME POST-as-GET: kid in header,
// jwk absent, empty payload.
func TestAuthenticatedRequestJWS(t *testing.T) {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		t.Fatal(err)
	}

	// ACME kid is the account URL, not a key thumbprint.
	// SignRaw uses the header's KID as-is (no conflict check).
	accountURL := "https://acme.example.com/acme/acct/12345"

	hdr := &AcmeHeader{
		RFCHeader: jwt.RFCHeader{KID: accountURL},
		URL:       "https://acme.example.com/acme/orders",
		Nonce:     "def456-server-nonce",
	}

	// POST-as-GET: nil payload produces empty payload segment.
	raw, err := signer.SignRaw(hdr, nil)
	if err != nil {
		t.Fatal(err)
	}

	// Verify protected header.
	headerJSON, err := base64.RawURLEncoding.DecodeString(string(raw.Protected))
	if err != nil {
		t.Fatal(err)
	}

	var decoded map[string]any
	if err := json.Unmarshal(headerJSON, &decoded); err != nil {
		t.Fatal(err)
	}

	if _, ok := decoded["typ"]; ok {
		t.Error("ACME header must not contain typ")
	}
	if decoded["kid"] != accountURL {
		t.Errorf("kid = %v, want %s", decoded["kid"], accountURL)
	}
	if _, ok := decoded["jwk"]; ok {
		t.Error("authenticated request must not contain jwk (mutually exclusive with kid)")
	}
	if decoded["url"] != "https://acme.example.com/acme/orders" {
		t.Errorf("url = %v", decoded["url"])
	}

	// Verify empty payload produces valid flattened JWS.
	flat, err := json.Marshal(raw)
	if err != nil {
		t.Fatal(err)
	}
	var flatMap map[string]string
	if err := json.Unmarshal(flat, &flatMap); err != nil {
		t.Fatalf("flattened JWS is not valid JSON: %v", err)
	}
	if flatMap["payload"] != "" {
		t.Errorf("POST-as-GET payload should be empty, got %q", flatMap["payload"])
	}
	if flatMap["signature"] == "" {
		t.Error("signature is empty")
	}
}
