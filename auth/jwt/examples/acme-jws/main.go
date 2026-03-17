// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example acme-jws demonstrates how to use the jwt library to produce
// ACME (RFC 8555) JWS messages with custom protected header fields.
//
// ACME uses JWS with non-standard header fields:
//   - url   -- the ACME endpoint URL being requested
//   - nonce -- anti-replay nonce obtained from the server
//   - jwk   -- the account's public key (for newAccount requests)
//   - kid   -- the account URL (for authenticated requests; mutually exclusive with jwk)
//
// ACME uses "flattened JWS JSON serialization" (RFC 7515 appendix A.7),
// not compact serialization. [jwt.Signer.SignRaw] handles the signing,
// and [jwt.RawJWT.MarshalJSON] produces the flattened JWS JSON:
//
//	{"protected":"...","payload":"...","signature":"..."}
//
// See acme_test.go for working examples of both newAccount (jwk) and
// authenticated (kid) request flows.
//
// https://www.rfc-editor.org/rfc/rfc8555
package main

import (
	"encoding/json"

	"github.com/therootcompany/golib/auth/jwt"
)

// AcmeHeader is the ACME JWS protected header. It embeds [jwt.RFCHeader]
// for alg and kid (both omitempty, so typ is never serialized -- ACME
// JWS does not use it), and adds the ACME-specific url, nonce, and jwk
// fields.
type AcmeHeader struct {
	jwt.RFCHeader
	URL   string          `json:"url"`
	Nonce string          `json:"nonce"`
	JWK   json.RawMessage `json:"jwk,omitempty"`
}

// NewAccountPayload is the ACME newAccount request body (RFC 8555 §7.3).
type NewAccountPayload struct {
	TermsOfServiceAgreed bool     `json:"termsOfServiceAgreed"`
	Contact              []string `json:"contact"`
}

func main() {}
