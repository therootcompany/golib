// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package keyfile_test

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/keyfile"
)

func mustFromPrivateKey(t *testing.T, signer crypto.Signer) *jwt.PrivateKey {
	t.Helper()
	pk, err := jwt.FromPrivateKey(signer, "")
	if err != nil {
		t.Fatal(err)
	}
	return pk
}

// --- PEM round-trip tests ---

func TestParsePrivatePEM_Ed25519(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	pk, err := keyfile.ParsePrivatePEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivatePEM: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be auto-computed from thumbprint")
	}
	if pk.Alg != "EdDSA" {
		t.Errorf("Alg: got %q, want %q", pk.Alg, "EdDSA")
	}
	if _, err := pk.PublicKey(); err != nil {
		t.Error("should be able to derive public key from loaded private key")
	}
}

func TestParsePrivatePEM_ECDSA(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalECPrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der})

	pk, err := keyfile.ParsePrivatePEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivatePEM: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be auto-computed")
	}
	if pk.Alg != "ES256" {
		t.Errorf("Alg: got %q, want %q", pk.Alg, "ES256")
	}
}

func TestParsePrivatePEM_RSA(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(priv),
	})

	pk, err := keyfile.ParsePrivatePEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivatePEM: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be auto-computed")
	}
	if pk.Alg != "RS256" {
		t.Errorf("Alg: got %q, want %q", pk.Alg, "RS256")
	}
}

func TestParsePublicPEM(t *testing.T) {
	_, pub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKIXPublicKey(pub.Public())
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	pk, err := keyfile.ParsePublicPEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePublicPEM: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be auto-computed")
	}
	if pk.Alg != "EdDSA" {
		t.Errorf("Alg: got %q, want %q", pk.Alg, "EdDSA")
	}
}

func TestParsePrivatePEM_UnsupportedBlockType(t *testing.T) {
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("dummy")})
	_, err := keyfile.ParsePrivatePEM(pemBytes)
	if !errors.Is(err, jwt.ErrUnsupportedFormat) {
		t.Fatalf("expected ErrUnsupportedFormat, got: %v", err)
	}
}

func TestParsePrivatePEM_NoPEMBlock(t *testing.T) {
	_, err := keyfile.ParsePrivatePEM([]byte("not pem data"))
	if !errors.Is(err, jwt.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got: %v", err)
	}
}

// --- DER round-trip tests ---

func TestParsePrivateDER_PKCS8(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}

	pk, err := keyfile.ParsePrivateDER(der)
	if err != nil {
		t.Fatalf("ParsePrivateDER: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be auto-computed")
	}
	if pk.Alg != "EdDSA" {
		t.Errorf("Alg: got %q, want %q", pk.Alg, "EdDSA")
	}
}

func TestParsePublicDER_SPKI(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(&priv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	pk, err := keyfile.ParsePublicDER(der)
	if err != nil {
		t.Fatalf("ParsePublicDER: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be auto-computed")
	}
	if pk.Alg != "ES384" {
		t.Errorf("Alg: got %q, want %q", pk.Alg, "ES384")
	}
}

func TestParsePrivateDER_InvalidData(t *testing.T) {
	_, err := keyfile.ParsePrivateDER([]byte("not der data"))
	if !errors.Is(err, jwt.ErrInvalidKey) {
		t.Fatalf("expected ErrInvalidKey, got: %v", err)
	}
}

// --- JWK parse wrapper tests ---

func TestParsePublicJWK(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := mustFromPrivateKey(t, priv)
	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}

	pk, err := jwt.ParsePublicJWK(data)
	if err != nil {
		t.Fatalf("ParsePublicJWK: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be set")
	}
	if pk.Key == nil {
		t.Error("Key should be set")
	}
}

func TestParsePrivateJWK(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := jwt.FromPrivateKey(priv, "test-kid")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(pk)
	if err != nil {
		t.Fatal(err)
	}

	parsed, err := jwt.ParsePrivateJWK(data)
	if err != nil {
		t.Fatalf("ParsePrivateJWK: %v", err)
	}
	if parsed.KID != "test-kid" {
		t.Errorf("KID: got %q, want %q", parsed.KID, "test-kid")
	}
	if _, err := parsed.PublicKey(); err != nil {
		t.Error("should be able to derive public key from parsed private key")
	}
}

// --- Load function tests (file-based) ---

func TestLoadPrivatePEM_FromFile(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pemBytes, 0600); err != nil {
		t.Fatal(err)
	}

	pk, err := keyfile.LoadPrivatePEM(path)
	if err != nil {
		t.Fatalf("LoadPrivatePEM: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be auto-computed")
	}
	if pk.Alg != "EdDSA" {
		t.Errorf("Alg: got %q, want %q", pk.Alg, "EdDSA")
	}
}

func TestLoadPublicJWK_FromFile(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	signer := mustFromPrivateKey(t, priv)
	pub, err := signer.PublicKey()
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(pub)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "key.jwk")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	pk, err := keyfile.LoadPublicJWK(path)
	if err != nil {
		t.Fatalf("LoadPublicJWK: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be set")
	}
}

// --- LoadWellKnownJWKs tests ---

func TestLoadWellKnownJWKs_SingleJWK(t *testing.T) {
	// A JWKS with a single key should parse and return one key.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwt.FromPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	jwks := jwt.WellKnownJWKs{Keys: []jwt.PublicKey{*pub}}
	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := keyfile.LoadWellKnownJWKs(path)
	if err != nil {
		t.Fatalf("LoadPublicJWKs: %v", err)
	}
	if len(loaded.Keys) != 1 {
		t.Fatalf("expected 1 key, got %d", len(loaded.Keys))
	}
	if loaded.Keys[0].KID != pub.KID {
		t.Errorf("KID: got %q, want %q", loaded.Keys[0].KID, pub.KID)
	}
}

func TestLoadWellKnownJWKs_MultipleKeys(t *testing.T) {
	// A JWKS with multiple keys of different types.
	_, edPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	edPub, err := jwt.FromPublicKey(edPriv.Public())
	if err != nil {
		t.Fatal(err)
	}

	ecPriv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecPub, err := jwt.FromPublicKey(&ecPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	rsaPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rsaPub, err := jwt.FromPublicKey(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatal(err)
	}

	jwks := jwt.WellKnownJWKs{Keys: []jwt.PublicKey{*edPub, *ecPub, *rsaPub}}
	data, err := json.Marshal(jwks)
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "jwks.json")
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatal(err)
	}

	loaded, err := keyfile.LoadWellKnownJWKs(path)
	if err != nil {
		t.Fatalf("LoadPublicJWKs: %v", err)
	}
	if len(loaded.Keys) != 3 {
		t.Fatalf("expected 3 keys, got %d", len(loaded.Keys))
	}

	// Verify each key retained its KID.
	wantKIDs := []string{edPub.KID, ecPub.KID, rsaPub.KID}
	for i, want := range wantKIDs {
		if loaded.Keys[i].KID != want {
			t.Errorf("key[%d] KID: got %q, want %q", i, loaded.Keys[i].KID, want)
		}
	}
}

func TestLoadWellKnownJWKs_PEMFile(t *testing.T) {
	// LoadWellKnownJWKs expects JWKS JSON, so a PEM file should fail.
	_, pub, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(pub.Public())
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	path := filepath.Join(t.TempDir(), "key.pem")
	if err := os.WriteFile(path, pemBytes, 0644); err != nil {
		t.Fatal(err)
	}

	_, err = keyfile.LoadWellKnownJWKs(path)
	if err == nil {
		t.Fatal("expected error for PEM file, got nil")
	}
}

func TestLoadWellKnownJWKs_FileNotFound(t *testing.T) {
	_, err := keyfile.LoadWellKnownJWKs(filepath.Join(t.TempDir(), "nonexistent.json"))
	if err == nil {
		t.Fatal("expected error for missing file, got nil")
	}
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("expected os.ErrNotExist, got: %v", err)
	}
}

func TestLoadWellKnownJWKs_InvalidContent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("this is not json"), 0644); err != nil {
		t.Fatal(err)
	}

	_, err := keyfile.LoadWellKnownJWKs(path)
	if err == nil {
		t.Fatal("expected error for corrupt content, got nil")
	}
}

// --- Save round-trip tests ---

func TestSavePublicJWK_RoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub, err := jwt.FromPublicKey(priv.Public())
	if err != nil {
		t.Fatal(err)
	}

	path := filepath.Join(t.TempDir(), "pub.jwk")
	if err := keyfile.SavePublicJWK(path, pub); err != nil {
		t.Fatalf("SavePublicJWK: %v", err)
	}

	loaded, err := keyfile.LoadPublicJWK(path)
	if err != nil {
		t.Fatalf("LoadPublicJWK: %v", err)
	}
	if loaded.KID != pub.KID {
		t.Errorf("KID mismatch: saved %q, loaded %q", pub.KID, loaded.KID)
	}

	// Verify file permissions are world-readable.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0644 {
		t.Errorf("file mode: got %o, want 0644", perm)
	}
}

func TestSavePrivateJWK_RoundTrip(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk, err := jwt.FromPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	kid, err := pk.Thumbprint()
	if err != nil {
		t.Fatal(err)
	}
	pk.KID = kid

	path := filepath.Join(t.TempDir(), "priv.jwk")
	if err := keyfile.SavePrivateJWK(path, pk); err != nil {
		t.Fatalf("SavePrivateJWK: %v", err)
	}

	loaded, err := keyfile.LoadPrivateJWK(path)
	if err != nil {
		t.Fatalf("LoadPrivateJWK: %v", err)
	}
	if loaded.KID != pk.KID {
		t.Errorf("KID mismatch: saved %q, loaded %q", pk.KID, loaded.KID)
	}

	// Verify file permissions are owner-only.
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0600 {
		t.Errorf("file mode: got %o, want 0600", perm)
	}
}

// --- KID consistency test ---

func TestKIDConsistency_PEM_vs_JWK(t *testing.T) {
	// Verify that a key loaded from PEM gets the same KID as the same key
	// loaded from JWK format.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	// Load via PEM.
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
	pemKey, err := keyfile.ParsePrivatePEM(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivatePEM: %v", err)
	}

	// Load via JWK.
	jwkPK, err := jwt.FromPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	jwkJSON, err := json.Marshal(jwkPK)
	if err != nil {
		t.Fatal(err)
	}
	jwkKey, err := jwt.ParsePrivateJWK(jwkJSON)
	if err != nil {
		t.Fatalf("ParsePrivateJWK: %v", err)
	}

	if pemKey.KID != jwkKey.KID {
		t.Errorf("KID mismatch: PEM=%q, JWK=%q", pemKey.KID, jwkKey.KID)
	}
}
