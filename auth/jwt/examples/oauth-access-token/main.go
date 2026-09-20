// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example oauth-access-token demonstrates OAuth 2.1 JWT access token
// validation per RFC 9068 using NewAccessTokenValidator with RequiredScopes.
//
// It mints an access token with JTI, ClientID, and Scope fields, then
// walks through the decode / verify / unmarshal / validate pipeline.
package main

import (
	"fmt"
	"log"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

func main() {
	// --- Setup: create a signer + verifier for demonstration ---
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		log.Fatal(err)
	}
	verifier := signer.Verifier()

	// --- Build access-token claims ---
	// RFC 9068 requires iss, sub, aud, exp, iat, jti, and client_id.
	claims := &jwt.TokenClaims{
		Iss:      "https://auth.example.com",
		Sub:      "user-42",
		Aud:      jwt.Listish{"https://api.example.com"},
		Exp:      time.Now().Add(time.Hour).Unix(),
		IAt:      time.Now().Unix(),
		JTI:      "tok-abc-123",
		ClientID: "mobile-app",
		Scope:    jwt.SpaceDelimited{"read:messages", "write:messages", "profile"},
	}

	// --- Mint an access token (typ: at+jwt) ---
	tok, err := jwt.NewAccessToken(claims)
	if err != nil {
		log.Fatal(err)
	}
	if err := signer.SignJWT(tok); err != nil {
		log.Fatal(err)
	}
	tokenStr, err := tok.Encode()
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("access token:", tokenStr[:40]+"...")

	// --- Decode (parse without verifying) ---
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		log.Fatal("decode:", err)
	}
	fmt.Printf("header typ: %s\n", jws.GetHeader().Typ)

	// --- Verify signature ---
	if err := verifier.Verify(jws); err != nil {
		log.Fatal("verify:", err)
	}
	fmt.Println("signature: OK")

	// --- Unmarshal claims ---
	var got jwt.TokenClaims
	if err := jws.UnmarshalClaims(&got); err != nil {
		log.Fatal("unmarshal:", err)
	}
	fmt.Printf("sub: %s  client_id: %s  jti: %s\n", got.Sub, got.ClientID, got.JTI)
	fmt.Printf("scope: %v\n", got.Scope)

	// --- Validate typ header + claims together ---
	validator := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"}, // allowed issuers
		[]string{"https://api.example.com"},  // allowed audiences
		0,                                    // grace period (0 = default 2s)
	)
	validator.RequiredScopes = []string{"read:messages", "profile"}

	// Thread header errors into Validate so all findings appear in one error.
	hdr := jws.GetHeader()
	var errs []error
	errs = hdr.IsAllowedTyp(errs, []string{"at+jwt"})
	if err := validator.Validate(errs, &got, time.Now()); err != nil {
		log.Fatal("validate:", err)
	}
	fmt.Println("claims: OK (typ, iss, sub, aud, exp, iat, jti, client_id, scope all valid)")

	// --- Demonstrate scope rejection ---
	strict := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},
		[]string{"https://api.example.com"},
		0,
	)
	strict.RequiredScopes = []string{"admin:delete"} // not in the token

	if err := strict.Validate(nil, &got, time.Now()); err != nil {
		fmt.Println("expected rejection:", err)
	}
}
