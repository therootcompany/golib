// Package rfc demonstrates a permissive RFC 7519 validator built on top of
// [jwt.IDTokenValidator]. It checks only exp and iat by default — everything
// else (iss, sub, aud, jti, auth_time, amr) is opt-in.
//
// Use this when tokens legitimately omit OIDC-required claims such as sub or
// aud. Prefer [jwt.IDTokenValidator] directly when you control token issuance
// and want full OIDC compliance enforced.
package rfc

import (
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// RFCValidator checks only what RFC 7519 requires by default — exp and iat.
// Iss, Aud, and Azp are checked when their allowlists are populated.
// Sub, JTI, AuthTime, and AMR require explicit opt-in via Expect* fields.
//
// This is a permissive alternative to [jwt.IDTokenValidator] for tokens
// that legitimately omit OIDC-required claims.
type RFCValidator struct {
	GracePeriod    time.Duration // 0 = DefaultGracePeriod (2s); negative = no tolerance
	MaxAge         time.Duration
	IgnoreExp      bool
	IgnoreNBF      bool     // rarely appropriate; nbf is a security boundary like exp
	IgnoreIat      bool
	Iss            []string // nil=unchecked, []=misconfigured, ["*"]=any, ["x"]=must match
	Aud            []string // token's aud must intersect list (if set)
	Azp            []string // token's azp must appear in list (if set)
	RequiredAMRs   []string // all of these must appear in the token's amr list
	MinAMRCount    int      // token's amr must have at least this many values; 0 = no minimum
	ExpectSub      bool     // if true, sub must be present (non-empty)
	ExpectJTI      bool     // if true, jti must be present (non-empty)
	ExpectAuthTime bool     // if true (or MaxAge > 0), auth_time is validated
	ExpectAMR      bool     // if true (or RequiredAMRs/MinAMRCount set), amr is validated
}

// Validate checks claims against RFC 7519 rules by delegating to
// [jwt.IDTokenValidator] with permissive defaults.
//
// The first return value contains every finding, including checks that are
// configured as "ignore" (soft). The second return value is non-nil only when
// a non-ignored check fails; use [errors.Is] on it for specific sentinels.
func (v *RFCValidator) Validate(claims jwt.Claims, now time.Time) ([]error, error) {
	return (&jwt.IDTokenValidator{
		GracePeriod:    v.GracePeriod,
		MaxAge:         v.MaxAge,
		IgnoreExp:      v.IgnoreExp,
		IgnoreNBF:      v.IgnoreNBF,
		IgnoreIat:      v.IgnoreIat,
		Iss:            v.Iss,
		Aud:            v.Aud,
		Azp:            v.Azp,
		RequiredAMRs:   v.RequiredAMRs,
		MinAMRCount:    v.MinAMRCount,
		IgnoreIss:      v.Iss == nil,
		IgnoreSub:      !v.ExpectSub,
		IgnoreAud:      v.Aud == nil,
		ExpectJTI:      v.ExpectJTI,
		ExpectAuthTime: v.ExpectAuthTime || v.MaxAge > 0,
	}).Validate(claims, now)
}
