// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example oidc-id-token demonstrates OIDC ID Token validation using
// jwt.StandardClaims, which carries the full set of OIDC profile, email,
// and phone fields alongside the core token claims.
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

	// Create an ID Token validator that checks iss, sub, aud, exp, iat,
	// and auth_time (per OIDC Core §3.1.3.7).
	validator := jwt.NewIDTokenValidator(
		[]string{"https://accounts.example.com"}, // allowed issuers
		[]string{"my-app-client-id"},             // allowed audiences
		nil,                                      // azp - no authorized-party restriction
		0,                                        // grace period (0 = default 2s)
	)

	// --- Mint an ID Token with OIDC profile and contact fields ---
	claims := &jwt.StandardClaims{
		TokenClaims: jwt.TokenClaims{
			Iss:      "https://accounts.example.com",
			Sub:      "user-42",
			Aud:      jwt.Listish{"my-app-client-id"},
			Exp:      time.Now().Add(time.Hour).Unix(),
			IAt:      time.Now().Unix(),
			AuthTime: time.Now().Unix(),
			Nonce:    "abc123",
		},

		// OIDC profile fields
		Name:              "Jane Doe",
		GivenName:         "Jane",
		FamilyName:        "Doe",
		PreferredUsername: "janedoe",
		Picture:           "https://example.com/janedoe/photo.jpg",
		Locale:            "en-US",

		// Contact fields with NullBool for *_verified
		Email:         "jane@example.com",
		EmailVerified: jwt.NullBool{Bool: true, Valid: true},

		PhoneNumber:         "+1-555-867-5309",
		PhoneNumberVerified: jwt.NullBool{Bool: false, Valid: true},
	}

	token, err := signer.SignToString(claims)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("signed ID token:", token[:40]+"...")

	// --- Decode, verify signature, unmarshal, validate ---
	jws, err := jwt.Decode(token)
	if err != nil {
		log.Fatal("decode:", err)
	}

	if err := verifier.Verify(jws); err != nil {
		log.Fatal("verify:", err)
	}

	var got jwt.StandardClaims
	if err := jws.UnmarshalClaims(&got); err != nil {
		log.Fatal("unmarshal:", err)
	}

	hdr := jws.GetHeader()
	var errs []error
	errs = hdr.IsAllowedTyp(errs, []string{"JWT"})
	if err := validator.Validate(errs, &got, time.Now()); err != nil {
		log.Fatal("validate:", err)
	}

	// --- Print the decoded OIDC claims ---
	fmt.Println()
	fmt.Println("=== ID Token Claims ===")
	fmt.Println("iss:          ", got.Iss)
	fmt.Println("sub:          ", got.Sub)
	fmt.Println("aud:          ", got.Aud)
	fmt.Println("nonce:        ", got.Nonce)
	fmt.Println()
	fmt.Println("name:         ", got.Name)
	fmt.Println("given_name:   ", got.GivenName)
	fmt.Println("family_name:  ", got.FamilyName)
	fmt.Println("preferred:    ", got.PreferredUsername)
	fmt.Println("picture:      ", got.Picture)
	fmt.Println("locale:       ", got.Locale)
	fmt.Println()
	fmt.Println("email:        ", got.Email)
	fmt.Printf("email_verified: value=%v valid=%v\n", got.EmailVerified.Bool, got.EmailVerified.Valid)
	fmt.Println("phone:        ", got.PhoneNumber)
	fmt.Printf("phone_verified: value=%v valid=%v\n", got.PhoneNumberVerified.Bool, got.PhoneNumberVerified.Valid)
}
