// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example dpop-jws demonstrates how to sign and decode a DPoP proof JWT
// (RFC 9449) with custom JOSE header fields.
//
// DPoP proof tokens use a custom typ ("dpop+jwt") and carry a server
// nonce in the header for replay protection. This example shows how to
// implement [jwt.SignableJWT] with a custom header struct.
//
// On the relying-party side, [jwt.DecodeRaw] + [jwt.RawJWT.UnmarshalHeader]
// gives you access to the custom fields.
//
// https://www.rfc-editor.org/rfc/rfc9449
package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// DPoPHeader extends the standard JOSE header with a DPoP nonce,
// as used in RFC 9449 (DPoP) proof tokens.
type DPoPHeader struct {
	jwt.RFCHeader
	Nonce string `json:"nonce,omitempty"`
}

// DPoPJWT is a custom JWT type that carries a DPoP header.
type DPoPJWT struct {
	jwt.RawJWT
	Header DPoPHeader
}

// GetHeader implements [jwt.VerifiableJWT].
func (d *DPoPJWT) GetHeader() jwt.RFCHeader { return d.Header.RFCHeader }

// SetHeader implements [jwt.SignableJWT]. It merges the signer's
// alg/kid into the DPoP header, then encodes the full protected header.
func (d *DPoPJWT) SetHeader(hdr jwt.Header) error {
	d.Header.RFCHeader = *hdr.GetRFCHeader()
	data, err := json.Marshal(d.Header)
	if err != nil {
		return err
	}
	d.Protected = []byte(base64.RawURLEncoding.EncodeToString(data))
	return nil
}

func main() {
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		log.Fatal(err)
	}

	claims := jwt.TokenClaims{
		Iss: "https://auth.example.com",
		Sub: "user123",
		Aud: jwt.Listish{"https://api.example.com"},
		Exp: time.Now().Add(time.Hour).Unix(),
		IAt: time.Now().Unix(),
	}

	dpop := &DPoPJWT{Header: DPoPHeader{
		RFCHeader: jwt.RFCHeader{Typ: "dpop+jwt"},
		Nonce:     "server-nonce-abc123",
	}}
	if err := dpop.SetClaims(&claims); err != nil {
		log.Fatal(err)
	}

	// SignJWT merges alg/kid from the key into our DPoP header.
	if err := signer.SignJWT(dpop); err != nil {
		log.Fatal(err)
	}
	tokenStr, err := jwt.Encode(dpop)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", tokenStr[:40]+"...")

	// --- Relying party side: decode with custom header ---

	raw, err := jwt.DecodeRaw(tokenStr)
	if err != nil {
		log.Fatal(err)
	}

	var h DPoPHeader
	if err := raw.UnmarshalHeader(&h); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("alg:   %s\n", h.Alg)
	fmt.Printf("kid:   %s\n", h.KID)
	fmt.Printf("typ:   %s\n", h.Typ)
	fmt.Printf("nonce: %s\n", h.Nonce)

	// Verify with the standard path.
	verifier := signer.Verifier()
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		log.Fatal(err)
	}
	if err := verifier.Verify(jws); err != nil {
		log.Fatal(err)
	}
	fmt.Println("signature: valid")
}
