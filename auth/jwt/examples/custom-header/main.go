// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example custom-header demonstrates reading a custom JOSE header field
// from a decoded JWT using [jwt.DecodeRaw] + [jwt.RawJWT.UnmarshalHeader].
//
// This is the relying-party pattern: you receive a token and need to
// inspect non-standard header fields before or after verification.
//
// For signing with custom headers, see the dpop-jws example.
package main

import (
	"fmt"
	"log"

	"github.com/therootcompany/golib/auth/jwt"
)

// MyHeader adds a nonce field to the standard JOSE header.
type MyHeader struct {
	jwt.RFCHeader
	Nonce string `json:"nonce,omitempty"`
}

func main() {
	// Given a token with a custom "nonce" header field...
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		log.Fatal(err)
	}
	token, err := signer.SignToString(&jwt.TokenClaims{Sub: "user123"})
	if err != nil {
		log.Fatal(err)
	}

	// Decode the raw segments, then unmarshal the header into your struct.
	raw, err := jwt.DecodeRaw(token)
	if err != nil {
		log.Fatal(err)
	}

	var h MyHeader
	if err := raw.UnmarshalHeader(&h); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("alg:   %s\n", h.Alg)
	fmt.Printf("kid:   %s\n", h.KID)
	fmt.Printf("nonce: %q\n", h.Nonce) // empty - this token has no nonce
}
