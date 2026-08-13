// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package keyfile

import (
	"encoding/json"
	"os"
	"strings"

	"github.com/therootcompany/golib/auth/jwt"
)

// LoadSharedSecretJWK loads a single HMAC shared secret JWK from a local file.
//
// The file must contain a JSON object with "kty":"oct" and "k" fields.
// If the JWK has no "kid" field, the KID is left unset.
func LoadSharedSecretJWK(path string) (*jwt.SharedSecret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.ParseSharedSecretJWK(data)
}

// LoadSharedSecretString reads a file as a string, trims whitespace, and
// uses the result directly as the shared secret bytes. The KID is left unset.
//
// Use this when the secret is stored as raw bytes in a plain-text file
// (e.g. openssl rand output file with a trailing newline).
func LoadSharedSecretString(path string) (*jwt.SharedSecret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	raw := strings.TrimSpace(string(data))
	return jwt.NewSharedSecret([]byte(raw), "")
}

// LoadSharedSecretBytes reads a file as raw bytes and uses them directly
// as the shared secret, without trimming. The KID is left unset.
//
// Use this when the file contents are binary or must be preserved exactly.
func LoadSharedSecretBytes(path string) (*jwt.SharedSecret, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return jwt.NewSharedSecret(data, "")
}

// --- Save functions (key => file) ---

// SaveSharedSecretJWK writes a shared secret as a JWK JSON file.
// The file is created with mode 0600 (owner-only).
func SaveSharedSecretJWK(path string, ss *jwt.SharedSecret) error {
	data, err := json.Marshal(ss)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	return os.WriteFile(path, data, 0600)
}

// SaveSharedSecret writes the raw secret bytes to a file as a plain-text string.
// The file is created with mode 0600 (owner-only).
func SaveSharedSecret(path string, ss *jwt.SharedSecret) error {
	return os.WriteFile(path, ss.Secret(), 0600)
}
