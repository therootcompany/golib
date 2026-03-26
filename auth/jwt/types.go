// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"encoding/json"
	"fmt"
	"strings"
)

// JOSE "typ" header values. The signer sets [DefaultTokenTyp] automatically.
// Use [NewAccessToken] or [JWT.SetTyp] to produce an OAuth 2.1 access token
// with [AccessTokenTyp].
const (
	DefaultTokenTyp = "JWT"    // standard JWT
	AccessTokenTyp  = "at+jwt" // OAuth 2.1 access token (RFC 9068 §2.1)
)

// Listish handles the JWT "aud" claim quirk: RFC 7519 §4.1.3 allows
// it to be either a single string or an array of strings.
//
// It unmarshals from both a single string ("https://auth.example.com") and
// an array (["https://api.example.com", "https://app.example.com"]).
// It marshals to a plain string for a single value and to an array for
// multiple values.
//
// https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1.3
type Listish []string

// UnmarshalJSON decodes both the string and []string forms of the "aud" claim.
// An empty string unmarshals to an empty (non-nil) slice, round-tripping with
// [Listish.MarshalJSON].
func (l *Listish) UnmarshalJSON(data []byte) error {
	var s string
	if err := json.Unmarshal(data, &s); err == nil {
		if s == "" {
			*l = Listish{}
			return nil
		}
		*l = Listish{s}
		return nil
	}
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return fmt.Errorf("aud must be a string or array of strings: %w: %w", ErrInvalidPayload, err)
	}
	*l = ss
	return nil
}

// IsZero reports whether the list is empty (nil or zero-length).
// Used by encoding/json with the omitzero tag option.
func (l Listish) IsZero() bool { return len(l) == 0 }

// MarshalJSON encodes the list as a plain string when there is one
// value, or as a JSON array for multiple values. An empty or nil Listish
// marshals as JSON null.
func (l Listish) MarshalJSON() ([]byte, error) {
	switch len(l) {
	case 0:
		return []byte("null"), nil
	case 1:
		return json.Marshal(l[0])
	default:
		return json.Marshal([]string(l))
	}
}

// SpaceDelimited is a slice of strings that marshals as a single
// space-separated string in JSON, per RFC 6749 §3.3.
//
// It has three-state semantics:
//   - nil: absent - the field is not present (omitted via omitzero)
//   - non-nil empty (SpaceDelimited{}): present but empty - marshals as ""
//   - populated (SpaceDelimited{"openid", "profile"}): marshals as "openid profile"
//
// UnmarshalJSON decodes a space-separated string back into a slice,
// preserving the distinction between nil (absent) and empty non-nil (present as "").
//
// https://www.rfc-editor.org/rfc/rfc6749.html#section-3.3
type SpaceDelimited []string

// UnmarshalJSON decodes a space-separated string into a slice.
// An empty string "" unmarshals to a non-nil empty SpaceDelimited{},
// preserving the distinction from a nil (absent) SpaceDelimited.
//
// As a compatibility extension, it also accepts a JSON array of strings,
// because some issuers (e.g. PaperOS) emit scope as [] instead of "".
func (s *SpaceDelimited) UnmarshalJSON(data []byte) error {
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		if str == "" {
			*s = SpaceDelimited{}
			return nil
		}
		*s = strings.Fields(str)
		return nil
	}

	// Fallback: accept a JSON array of strings (non-standard but used in the wild).
	var ss []string
	if err := json.Unmarshal(data, &ss); err != nil {
		return fmt.Errorf("space-delimited must be a string or array of strings: %w: %w", ErrInvalidPayload, err)
	}
	if ss == nil {
		*s = SpaceDelimited{}
	} else {
		*s = SpaceDelimited(ss)
	}
	return nil
}

// IsZero reports whether the slice is absent (nil).
// Used by encoding/json with the omitzero tag option to omit the field
// when it is nil, while still marshaling a non-nil empty SpaceDelimited as "".
func (s SpaceDelimited) IsZero() bool { return s == nil }

// MarshalJSON encodes the slice as a single space-separated string.
// A nil SpaceDelimited marshals as JSON null (but is typically omitted via omitzero).
// A non-nil empty SpaceDelimited marshals as the empty string "".
func (s SpaceDelimited) MarshalJSON() ([]byte, error) {
	if s == nil {
		return []byte("null"), nil
	}
	return json.Marshal(strings.Join(s, " "))
}

// NullBool represents a boolean that can be null, true, or false.
// Used for OIDC *_verified fields where null means "not applicable"
// (the corresponding value is absent), false means "present but not
// verified", and true means "verified".
type NullBool struct {
	Bool  bool
	Valid bool // Valid is true if Bool is not NULL
}

// IsZero reports whether nb is the zero value (not valid).
// Used by encoding/json with the omitzero tag option.
func (nb NullBool) IsZero() bool { return !nb.Valid }

// MarshalJSON encodes the NullBool as JSON. If !Valid, it outputs null;
// otherwise it outputs true or false.
func (nb NullBool) MarshalJSON() ([]byte, error) {
	if !nb.Valid {
		return []byte("null"), nil
	}
	if nb.Bool {
		return []byte("true"), nil
	}
	return []byte("false"), nil
}

// UnmarshalJSON decodes a JSON value into a NullBool.
// null -> {false, false}; true -> {true, true}; false -> {false, true}.
func (nb *NullBool) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		nb.Bool = false
		nb.Valid = false
		return nil
	}
	var b bool
	if err := json.Unmarshal(data, &b); err != nil {
		return err
	}
	nb.Bool = b
	nb.Valid = true
	return nil
}
