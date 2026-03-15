package examplejwk_test

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"testing"

	"github.com/therootcompany/golib/auth/examplejwk"
)

func TestPublicKeyRoundTrip_EC(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		priv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		orig := examplejwk.PublicKey{
			Key: &priv.PublicKey,
			KID: "test-ec",
			Use: "sig",
		}

		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		var got examplejwk.PublicKey
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		gotEC, ok := got.Key.(*ecdsa.PublicKey)
		if !ok {
			t.Fatalf("got key type %T, want *ecdsa.PublicKey", got.Key)
		}
		if !priv.PublicKey.Equal(gotEC) {
			t.Errorf("EC public key mismatch after round-trip on curve %s", curve.Params().Name)
		}
		if got.KID != orig.KID || got.Use != orig.Use {
			t.Errorf("metadata mismatch: got KID=%q Use=%q, want KID=%q Use=%q",
				got.KID, got.Use, orig.KID, orig.Use)
		}
	}
}

func TestPublicKeyRoundTrip_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	orig := examplejwk.PublicKey{
		Key: &priv.PublicKey,
		KID: "test-rsa",
		Use: "sig",
		Alg: "RS256",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got examplejwk.PublicKey
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	gotRSA, ok := got.Key.(*rsa.PublicKey)
	if !ok {
		t.Fatalf("got key type %T, want *rsa.PublicKey", got.Key)
	}
	if !priv.PublicKey.Equal(gotRSA) {
		t.Errorf("RSA public key mismatch after round-trip")
	}
	if got.KID != orig.KID || got.Alg != orig.Alg {
		t.Errorf("metadata mismatch: got KID=%q Alg=%q, want KID=%q Alg=%q",
			got.KID, got.Alg, orig.KID, orig.Alg)
	}
}

func TestPublicKeyRoundTrip_EdDSA(t *testing.T) {
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	orig := examplejwk.PublicKey{
		Key: pub,
		KID: "test-eddsa",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got examplejwk.PublicKey
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	gotPub, ok := got.Key.(ed25519.PublicKey)
	if !ok {
		t.Fatalf("got key type %T, want ed25519.PublicKey", got.Key)
	}
	if !pub.Equal(gotPub) {
		t.Errorf("Ed25519 public key mismatch after round-trip")
	}
}

func TestPrivateKeyRoundTrip_EC(t *testing.T) {
	for _, curve := range []elliptic.Curve{elliptic.P256(), elliptic.P384(), elliptic.P521()} {
		origPriv, err := ecdsa.GenerateKey(curve, rand.Reader)
		if err != nil {
			t.Fatalf("generate EC key: %v", err)
		}
		orig := examplejwk.PrivateKey{
			Key: origPriv,
			KID: "test-ec-priv",
		}

		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("marshal: %v", err)
		}

		var got examplejwk.PrivateKey
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("unmarshal: %v", err)
		}

		gotEC, ok := got.Key.(*ecdsa.PrivateKey)
		if !ok {
			t.Fatalf("got key type %T, want *ecdsa.PrivateKey", got.Key)
		}
		if !origPriv.Equal(gotEC) {
			t.Errorf("EC private key mismatch after round-trip on curve %s", curve.Params().Name)
		}
	}
}

func TestPrivateKeyRoundTrip_RSA(t *testing.T) {
	origPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	orig := examplejwk.PrivateKey{
		Key: origPriv,
		KID: "test-rsa-priv",
		Use: "sig",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got examplejwk.PrivateKey
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	gotRSA, ok := got.Key.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("got key type %T, want *rsa.PrivateKey", got.Key)
	}
	if !origPriv.Equal(gotRSA) {
		t.Errorf("RSA private key mismatch after round-trip")
	}
	if got.KID != orig.KID || got.Use != orig.Use {
		t.Errorf("metadata mismatch: got KID=%q Use=%q, want KID=%q Use=%q",
			got.KID, got.Use, orig.KID, orig.Use)
	}
}

func TestPrivateKeyRoundTrip_EdDSA(t *testing.T) {
	_, origPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate Ed25519 key: %v", err)
	}
	orig := examplejwk.PrivateKey{
		Key: origPriv,
		KID: "test-eddsa-priv",
	}

	data, err := json.Marshal(orig)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}

	var got examplejwk.PrivateKey
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}

	gotEdDSA, ok := got.Key.(ed25519.PrivateKey)
	if !ok {
		t.Fatalf("got key type %T, want ed25519.PrivateKey", got.Key)
	}
	if !origPriv.Equal(gotEdDSA) {
		t.Errorf("Ed25519 private key mismatch after round-trip")
	}
}
