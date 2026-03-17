// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example mfa-validator demonstrates application-level AMR validation
// after [jwt.Validator.Validate]. The jwt package intentionally
// does not enforce AMR rules because there is no standard registry of
// values - each provider defines its own. This example shows how to
// check required authentication methods and minimum factor counts in
// your own code.
package main

import (
	"errors"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// MFAPolicy defines what authentication methods a token must contain.
type MFAPolicy struct {
	// RequiredAMRs lists method values that must all appear in the
	// token's amr claim (e.g. ["pwd", "otp"]).
	RequiredAMRs []string

	// MinFactors is the minimum number of distinct amr values the
	// token must contain. 0 means no minimum.
	MinFactors int
}

// Validate checks that claims.AMR satisfies the policy.
func (p *MFAPolicy) Validate(claims jwt.Claims) error {
	amr := claims.GetTokenClaims().AMR

	if len(amr) == 0 {
		return fmt.Errorf("amr claim is missing or empty: %w", jwt.ErrMissingClaim)
	}

	for _, required := range p.RequiredAMRs {
		if !slices.Contains(amr, required) {
			return fmt.Errorf("amr missing %q: %w", required, jwt.ErrInvalidClaim)
		}
	}

	if p.MinFactors > 0 && len(amr) < p.MinFactors {
		return fmt.Errorf(
			"amr has %d factor(s), need at least %d: %w",
			len(amr), p.MinFactors, jwt.ErrInvalidClaim,
		)
	}

	return nil
}

func main() {
	// --- Issuer side: create and sign a token ---
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		log.Fatal(err)
	}

	claims := &jwt.TokenClaims{
		Iss:      "https://example.com",
		Sub:      "user123",
		Aud:      jwt.Listish{"myapp"},
		Exp:      time.Now().Add(time.Hour).Unix(),
		IAt:      time.Now().Unix(),
		AMR:      []string{"pwd", "otp"},
		AuthTime: time.Now().Unix(),
	}

	tokenStr, err := signer.SignToString(claims)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println("token:", tokenStr[:40]+"...")

	// --- Relying party side: verify => validate => check MFA ---

	// 1. Decode and verify the signature.
	jws, err := jwt.Decode(tokenStr)
	if err != nil {
		log.Fatal(err)
	}
	verifier := signer.Verifier()
	if err := verifier.Verify(jws); err != nil {
		log.Fatal(err)
	}

	// 2. Unmarshal and validate standard claims.
	var got jwt.TokenClaims
	if err := jws.UnmarshalClaims(&got); err != nil {
		log.Fatal(err)
	}
	v := jwt.NewIDTokenValidator(
		[]string{"https://example.com"},
		[]string{"myapp"},
		nil, // azp
		0,   // grace period (0 = default 2s)
	)
	if err := v.Validate(nil, &got, time.Now()); err != nil {
		log.Fatal(err)
	}

	// 3. Check MFA policy - this is the application-level step.
	mfa := &MFAPolicy{
		RequiredAMRs: []string{"pwd", "otp"},
		MinFactors:   2,
	}
	if err := mfa.Validate(&got); err != nil {
		log.Fatal("MFA check failed:", err)
	}
	fmt.Println("MFA check: passed")

	// --- Demonstrate a failure case ---
	weakClaims := &jwt.TokenClaims{
		Iss: "https://example.com",
		Sub: "user456",
		Aud: jwt.Listish{"myapp"},
		Exp: time.Now().Add(time.Hour).Unix(),
		IAt: time.Now().Unix(),
		AMR: []string{"pwd"}, // only one factor
	}
	if err := mfa.Validate(weakClaims); err != nil {
		fmt.Println("weak token rejected:", errors.Unwrap(err))
	}
}
