// Package rfc demonstrates a permissive RFC 7519 validator using
// [jwt.Validator] with a minimal Checks bitmask.
//
// Use this approach when tokens legitimately omit OIDC-required claims
// such as sub or aud. Prefer [jwt.NewIDTokenValidator] or
// [jwt.NewAccessTokenValidator] when you control token issuance and
// want full compliance enforced.
package rfc

import (
	"github.com/therootcompany/golib/auth/jwt"
)

// NewRFCValidator returns a [jwt.Validator] that checks only what
// RFC 7519 requires by default: exp, iat, and nbf.
//
// Iss and aud are checked when their allowlists are non-nil.
// Additional checks can be enabled by OR-ing more Check* flags
// onto the returned Validator's Checks field.
func NewRFCValidator(iss, aud []string) *jwt.Validator {
	return &jwt.Validator{
		Checks: jwt.ChecksConfigured | jwt.CheckExp | jwt.CheckIAt | jwt.CheckNBf,
		Iss:    iss,
		Aud:    aud,
	}
}
