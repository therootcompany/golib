// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

// TokenClaims holds the standard JWT and OIDC claims: the RFC 7519
// registered claim names (iss, sub, aud, exp, nbf, iat, jti), the OIDC-specific
// authentication event fields (auth_time, nonce, amr, azp), and OAuth 2.1
// access token fields (client_id, scope).
//
// For OIDC UserInfo profile fields (name, email, phone, locale, etc.),
// use [StandardClaims] instead - it embeds TokenClaims and adds §5.1 fields.
//
// https://www.rfc-editor.org/rfc/rfc7519.html
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
// https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2
//
// Embed TokenClaims or StandardClaims in your own claims struct to
// satisfy [Claims] for free via Go's method promotion - zero boilerplate:
//
//	type AppClaims struct {
//	    jwt.TokenClaims                // promotes GetTokenClaims()
//	    RoleList string `json:"roles"`
//	}
//	// AppClaims now satisfies Claims automatically.
type TokenClaims struct {
	Iss      string         `json:"iss"`                 // Issuer (a.k.a. Provider ID) - the auth provider's identifier
	Sub      string         `json:"sub"`                 // Subject (a.k.a. Account ID) - pairwise id between provider and account
	Aud      Listish        `json:"aud,omitzero"`        // Audience (a.k.a. Service Provider) - the intended token recipient
	Exp      int64          `json:"exp"`                 // Expiration - the token is not valid after this Unix time
	NBf      int64          `json:"nbf,omitempty"`       // Not Before - the token is not valid until this Unix time
	IAt      int64          `json:"iat"`                 // Issued At - when the token was signed
	JTI      string         `json:"jti,omitempty"`       // JSON Web Token ID - unique identifier for replay/revocation
	AuthTime int64          `json:"auth_time,omitempty"` // Authentication Time - when the end-user last authenticated
	Nonce    string         `json:"nonce,omitempty"`     // Nonce - ties an ID Token to a specific auth request
	AMR      []string       `json:"amr,omitempty"`       // Authentication Method Reference - how the account was signed in
	AzP      string         `json:"azp,omitempty"`       // Authorized Party (a.k.a. Relying Party) - the intended token consumer
	ClientID string         `json:"client_id,omitempty"` // Client ID - the OAuth client that requested the token
	Scope    SpaceDelimited `json:"scope,omitzero"`      // Scope - granted OAuth 2.1 scopes
}

// GetTokenClaims implements [Claims].
// Any struct embedding TokenClaims gets this method for free via promotion.
func (tc *TokenClaims) GetTokenClaims() *TokenClaims { return tc }

// Claims is implemented for free by any struct that embeds [TokenClaims].
//
//	type AppClaims struct {
//	    jwt.TokenClaims           // promotes GetTokenClaims() - zero boilerplate
//	    RoleList string `json:"roles"`
//	}
type Claims interface {
	GetTokenClaims() *TokenClaims
}

// StandardClaims embeds [TokenClaims] and adds the OIDC Core §5.1
// UserInfo standard profile claims. Embed StandardClaims in your own type to
// get all fields with zero boilerplate:
//
//	type AppClaims struct {
//	    jwt.StandardClaims       // promotes GetTokenClaims()
//	    Roles []string `json:"roles"`
//	}
//
// https://openid.net/specs/openid-connect-core-1_0.html#StandardClaims
type StandardClaims struct {
	TokenClaims // promotes GetTokenClaims() - satisfies Claims automatically

	// Profile fields (OIDC Core §5.1)
	Name              string `json:"name,omitempty"`
	GivenName         string `json:"given_name,omitempty"`
	FamilyName        string `json:"family_name,omitempty"`
	MiddleName        string `json:"middle_name,omitempty"`
	Nickname          string `json:"nickname,omitempty"`
	PreferredUsername string `json:"preferred_username,omitempty"`
	Profile           string `json:"profile,omitempty"` // URL of end-user's profile page
	Picture           string `json:"picture,omitempty"` // URL of end-user's profile picture
	Website           string `json:"website,omitempty"` // URL of end-user's web page

	// Contact fields
	Email               string   `json:"email,omitempty"`
	EmailVerified       NullBool `json:"email_verified,omitzero"`
	PhoneNumber         string   `json:"phone_number,omitempty"`
	PhoneNumberVerified NullBool `json:"phone_number_verified,omitzero"`

	// Locale / time fields
	Gender    string `json:"gender,omitempty"`
	Birthdate string `json:"birthdate,omitempty"` // YYYY, YYYY-MM, or YYYY-MM-DD (§5.1)
	Zoneinfo  string `json:"zoneinfo,omitempty"`  // IANA tz, e.g. "Europe/Paris"
	Locale    string `json:"locale,omitempty"`    // BCP 47, e.g. "en-US"

	UpdatedAt int64 `json:"updated_at,omitempty"` // seconds since Unix epoch
}
