// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example custom-header demonstrates how to decode a JWT with custom
// JOSE header fields using [jwt.DecodeRaw] and [jwt.RawJWT.UnmarshalHeader].
//
// The standard [jwt.Decode] only parses alg, kid, and typ. When you need
// access to additional header fields (nonce, jwk, x5c, etc.), use
// DecodeRaw to get the raw segments, then UnmarshalHeader into your
// own struct.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
	"github.com/therootcompany/golib/auth/jwt/jwk"
)

// DPoPHeader extends the standard JOSE header with a DPoP nonce and
// an embedded JWK, as used in RFC 9449 (DPoP) proof tokens.
type DPoPHeader struct {
	jwt.Header
	Nonce string          `json:"nonce,omitempty"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
}

func main() {
	// --- Issuer side: sign a token ---
	pk, err := jwk.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jwt.NewSigner([]jwk.PrivateKey{*pk})
	if err != nil {
		log.Fatal(err)
	}
	claims := jwt.IDTokenClaims{
		Iss: "https://example.com",
		Sub: "user123",
		Aud: jwt.Audience{"myapp"},
		Exp: time.Now().Add(time.Hour).Unix(),
		Iat: time.Now().Unix(),
	}
	tokenStr, err := signer.SignToString(&claims)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", tokenStr[:40]+"...")

	// --- Relying party side: decode with custom header ---

	// DecodeRaw splits the segments without parsing the header JSON.
	raw, err := jwt.DecodeRaw(tokenStr)
	if err != nil {
		log.Fatal(err)
	}

	// UnmarshalHeader base64-decodes and JSON-unmarshals the protected
	// header into your custom struct. Standard fields (alg, kid, typ)
	// are captured via the embedded jwt.Header.
	var h DPoPHeader
	if err := raw.UnmarshalHeader(&h); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("alg:   %s\n", h.Alg)
	fmt.Printf("kid:   %s\n", h.KID)
	fmt.Printf("typ:   %s\n", h.Typ)
	fmt.Printf("nonce: %s\n", h.Nonce) // empty for this token

	// For verification, use the standard Decode + Verify path.
	// DecodeRaw is only needed when you want the custom header fields.
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		log.Fatal(err)
	}
	verifier := signer.Verifier()
	if err := verifier.Verify(jws); err != nil {
		log.Fatal(err)
	}
	fmt.Println("signature: valid")

	// UnmarshalHeader also works on *JWS (promoted from RawJWT).
	var h2 DPoPHeader
	if err := jws.UnmarshalHeader(&h2); err != nil {
		log.Fatal(err)
	}
	fmt.Printf("via JWS — alg: %s, kid: %s\n", h2.Alg, h2.KID)
}
