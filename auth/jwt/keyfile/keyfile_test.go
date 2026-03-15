// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package keyfile_test

import (
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
	if pk.Signer == nil {
		t.Error("Signer should be set")
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
	signer := &jwt.PrivateKey{Signer: priv}
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
	if pk.CryptoPublicKey == nil {
		t.Error("CryptoPublicKey should be set")
	}
}

func TestParsePrivateJWK(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pk := jwt.PrivateKey{Signer: priv, KID: "test-kid"}
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
	if parsed.Signer == nil {
		t.Error("Signer should be set")
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
	signer := &jwt.PrivateKey{Signer: priv}
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

func TestLoadPrivatePEM_FileURI(t *testing.T) {
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

	// Test file:///path form.
	pk, err := keyfile.LoadPrivatePEM("file://" + path)
	if err != nil {
		t.Fatalf("LoadPrivatePEM with file:// URI: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be auto-computed")
	}
}

// --- Source resolution tests ---

func TestFileURIToPath(t *testing.T) {
	// This tests indirectly via LoadPrivatePEM with file: URIs.
	// The fileURIToPath logic is tested through the Load functions.
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

	// file:///absolute/path form
	pk, err := keyfile.LoadPrivatePEM("file://" + path)
	if err != nil {
		t.Fatalf("file:// URI: %v", err)
	}
	if pk.KID == "" {
		t.Error("KID should be set")
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
	jwkPK := jwt.PrivateKey{Signer: priv}
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
