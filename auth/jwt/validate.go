// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

package jwt

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// ValidationError represents a single claim validation failure with a
// machine-readable code suitable for API responses.
//
// Code values and their meanings:
//
//	token_expired       - exp claim is in the past
//	token_not_yet_valid - nbf claim is in the future
//	future_issued_at    - iat claim is in the future
//	future_auth_time    - auth_time claim is in the future
//	auth_time_exceeded  - auth_time exceeds max age
//	insufficient_scope  - required scopes not granted
//	missing_claim       - a required claim is absent
//	invalid_claim       - a claim value is wrong (bad iss, aud, etc.)
//	server_error        - server-side validator config error (treat as 500)
//	unknown_error       - unrecognized sentinel (should not occur)
//
// ValidationError satisfies [error] and supports [errors.Is] via [Unwrap]
// against the underlying sentinel (e.g., [ErrAfterExp], [ErrMissingClaim]).
//
// JSON serialization produces {"code": "...", "description": "..."}
// for direct use in API error responses.
//
// Use [ValidationErrors] to extract these from the error returned by
// [Validator.Validate]:
//
//	err := v.Validate(nil, &claims, time.Now())
//	for _, ve := range jwt.ValidationErrors(err) {
//	    log.Printf("code=%s: %s", ve.Code, ve.Description)
//	}
type ValidationError struct {
	Code        string `json:"code"`        // machine-readable code (see table above)
	Description string `json:"description"` // human-readable detail, prefixed with claim name
	Err         error  `json:"-"`           // sentinel for errors.Is / Unwrap
}

// Error implements [error]. Returns the human-readable description.
func (e *ValidationError) Error() string { return e.Description }

// Unwrap returns the underlying sentinel error for use with [errors.Is].
func (e *ValidationError) Unwrap() error { return e.Err }

// ValidationErrors extracts structured [*ValidationError] values from the
// error returned by [Validator.Validate] or [TokenClaims.Errors].
//
// Non-ValidationError entries (such as the server-time context line) are
// skipped. Returns nil if err is nil or contains no ValidationError values.
func ValidationErrors(err error) []*ValidationError {
	if err == nil {
		return nil
	}
	var errs []error
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		errs = joined.Unwrap()
	} else {
		errs = []error{err}
	}
	result := make([]*ValidationError, 0, len(errs))
	for _, e := range errs {
		if ve, ok := e.(*ValidationError); ok {
			result = append(result, ve)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// GetOAuth2Error returns the OAuth 2.0 error code for the validation error
// returned by [Validator.Validate] or [TokenClaims.Errors].
//
// Returns one of:
//
//   - "invalid_token" - the token is expired, malformed, or otherwise invalid
//   - "insufficient_scope" - the token lacks required scopes
//   - "server_error" - server-side misconfiguration (treat as HTTP 500)
//
// per RFC 6750 §3.1. When multiple validation failures exist, the most severe
// code wins (server_error > insufficient_scope > invalid_token).
//
// Returns "" if err is nil or contains no [*ValidationError] values.
// Use err.Error() for the human-readable description:
//
//	err := v.Validate(nil, &claims, time.Now())
//	if code := jwt.GetOAuth2Error(err); code != "" {
//	    vals := url.Values{"error": {code}, "error_description": {err.Error()}}
//	    http.Redirect(w, r, redirectURI+"?"+vals.Encode(), http.StatusFound)
//	}
func GetOAuth2Error(err error) (oauth2Error string) {
	ves := ValidationErrors(err)
	if len(ves) == 0 {
		return ""
	}

	// Pick the most severe OAuth code across all errors.
	code := "invalid_token"
	for _, ve := range ves {
		switch {
		case errors.Is(ve.Err, ErrMisconfigured):
			code = "server_error"
		case errors.Is(ve.Err, ErrInsufficientScope) && code != "server_error":
			code = "insufficient_scope"
		}
	}
	return code
}

// appendError constructs a [*ValidationError] and appends it to the slice.
// sentinel is the error for [errors.Is] matching; format and args produce the
// human-readable description (conventionally prefixed with the claim name,
// e.g. "exp: expired 5m ago").
func appendError(errs []error, sentinel error, format string, args ...any) []error {
	return append(errs, &ValidationError{
		Code:        codeFor(sentinel),
		Description: fmt.Sprintf(format, args...),
		Err:         sentinel,
	})
}

// isTimeSentinel reports whether the sentinel is a time-related claim error.
func isTimeSentinel(sentinel error) bool {
	return errors.Is(sentinel, ErrAfterExp) ||
		errors.Is(sentinel, ErrBeforeNBf) ||
		errors.Is(sentinel, ErrBeforeIAt) ||
		errors.Is(sentinel, ErrBeforeAuthTime) ||
		errors.Is(sentinel, ErrAfterAuthMaxAge)
}

// codeFor maps a sentinel error to a machine-readable code string.
func codeFor(sentinel error) string {
	switch {
	case errors.Is(sentinel, ErrAfterExp):
		return "token_expired"
	case errors.Is(sentinel, ErrBeforeNBf):
		return "token_not_yet_valid"
	case errors.Is(sentinel, ErrBeforeIAt):
		return "future_issued_at"
	case errors.Is(sentinel, ErrBeforeAuthTime):
		return "future_auth_time"
	case errors.Is(sentinel, ErrAfterAuthMaxAge):
		return "auth_time_exceeded"
	case errors.Is(sentinel, ErrInsufficientScope):
		return "insufficient_scope"
	case errors.Is(sentinel, ErrMissingClaim):
		return "missing_claim"
	case errors.Is(sentinel, ErrInvalidTyp):
		return "invalid_typ"
	case errors.Is(sentinel, ErrInvalidClaim):
		return "invalid_claim"
	case errors.Is(sentinel, ErrMisconfigured):
		return "server_error"
	default:
		return "unknown_error"
	}
}

// formatDuration formats a duration as a human-readable string with days,
// hours, minutes, seconds, and milliseconds.
func formatDuration(d time.Duration) string {
	if d < 0 {
		d = -d
	}
	days := int(d / (24 * time.Hour))
	d -= time.Duration(days) * 24 * time.Hour
	hours := int(d / time.Hour)
	d -= time.Duration(hours) * time.Hour
	minutes := int(d / time.Minute)
	d -= time.Duration(minutes) * time.Minute
	seconds := int(d / time.Second)

	var parts []string
	if days > 0 {
		parts = append(parts, fmt.Sprintf("%dd", days))
	}
	if hours > 0 {
		parts = append(parts, fmt.Sprintf("%dh", hours))
	}
	if minutes > 0 {
		parts = append(parts, fmt.Sprintf("%dm", minutes))
	}
	if seconds > 0 {
		parts = append(parts, fmt.Sprintf("%ds", seconds))
	}
	if len(parts) == 0 {
		// Sub-second duration: fall back to milliseconds.
		millis := int(d / time.Millisecond)
		parts = append(parts, fmt.Sprintf("%dms", millis))
	}

	return strings.Join(parts, " ")
}

// defaultGracePeriod is the tolerance applied to exp, iat, and auth_time checks
// when Validator.GracePeriod is zero.
//
// It should be set to at least 2s in most cases to account for practical edge
// cases of corresponding systems having even a millisecond of clock skew between
// them and the offset of their respective implementations truncating, flooring,
// ceiling, or rounding seconds differently.
//
// For example: If 1.999 is truncated to 1 and 2.001 is ceiled to 3, then there
// is a 2 second difference.
//
// This will very rarely affect calculations on exp (and hopefully a client knows
// better than to ride the very millisecond of expiration), but it can very
// frequently affect calculations on iat and nbf on distributed production
// systems.
const defaultGracePeriod = 2 * time.Second

// Checks is a bitmask that selects which claim validations [Validator]
// performs. Combine with OR:
//
//	v := &jwt.Validator{
//	    Checks: jwt.CheckIss | jwt.CheckExp,
//	    Iss:    []string{"https://example.com"},
//	}
//
// Use [NewIDTokenValidator] or [NewAccessTokenValidator] for sensible defaults.
type Checks uint32

const (
	// ChecksConfigured is a sentinel bit that distinguishes a deliberately
	// configured Checks value from the zero value. Constructors like
	// [NewIDTokenValidator] set it automatically. Struct-literal users
	// should include it so that [Validator.Validate] does not reject the
	// Validator as unconfigured.
	ChecksConfigured Checks = 1 << iota
	CheckIss                // validate issuer
	CheckSub                // validate subject presence
	CheckAud                // validate audience
	CheckExp                // validate expiration
	CheckNBf                // validate not-before
	CheckIAt                // validate issued-at is not in the future
	CheckClientID           // validate client_id presence
	CheckJTI                // validate jti presence
	CheckAuthTime           // validate auth_time
	CheckAzP                // validate authorized party
	CheckScope              // validate scope presence
)

// resolveSkew converts a GracePeriod configuration value to a skew duration.
// Zero means use [defaultGracePeriod]; negative means no tolerance.
func resolveSkew(gracePeriod time.Duration) time.Duration {
	if gracePeriod == 0 {
		return defaultGracePeriod
	}
	if gracePeriod < 0 {
		return 0
	}
	return gracePeriod
}

// Validator checks JWT claims for both ID tokens and access tokens.
//
// Use [NewIDTokenValidator] or [NewAccessTokenValidator] to create one with
// sensible defaults for the token type. You can also construct a Validator
// literal with a custom [Checks] bitmask - but you must OR at least one
// Check* flag or set Iss/Aud/AzP/RequiredScopes/MaxAge, otherwise Validate
// returns a misconfiguration error (a zero-value Validator is never valid).
//
// Iss, Aud, and AzP distinguish nil from empty: nil means unconfigured
// (no check unless the corresponding Check* flag is set), a non-nil empty
// slice is always a misconfiguration error (the empty set allows nothing),
// and ["*"] accepts any non-empty value. A non-nil slice forces its check
// regardless of the Checks bitmask.
//
// GracePeriod is applied to exp, nbf, iat, and auth_time (including maxAge)
// to tolerate minor clock differences between distributed systems. If zero,
// the default grace period (2s) is used. Set to a negative value to disable
// skew tolerance entirely.
//
// Explicit configuration (non-nil Iss/Aud/AzP, non-empty RequiredScopes,
// MaxAge > 0) forces the corresponding check regardless of the Checks bitmask.
type Validator struct {
	Checks         Checks
	GracePeriod    time.Duration // 0 = default (2s); negative = no tolerance
	MaxAge         time.Duration
	Iss            []string // nil=unchecked, []=misconfigured, ["*"]=any, ["x"]=must match
	Aud            []string // nil=unchecked, []=misconfigured, ["*"]=any, ["x"]=must intersect
	AzP            []string // nil=unchecked, []=misconfigured, ["*"]=any, ["x"]=must match
	RequiredScopes []string // all of these must appear in the token's scope
}

// NewIDTokenValidator returns a [Validator] configured for OIDC Core §2 ID Tokens.
//
// Pass the allowed issuers and audiences, or nil to skip that check.
// Use []string{"*"} to require the claim be present without restricting its value.
//
// Checks enabled by default: iss, sub, aud, exp, iat, auth_time, azp
// Not checked: amr, nonce, nbf, jti, client_id, and scope.
// Adjust by OR-ing or masking the returned Validator's Checks field.
//
// https://openid.net/specs/openid-connect-core-1_0.html#IDToken
func NewIDTokenValidator(iss, aud, azp []string) *Validator {
	checks := ChecksConfigured | CheckSub | CheckExp | CheckIAt | CheckAuthTime
	if iss != nil {
		checks |= CheckIss
	}
	if aud != nil {
		checks |= CheckAud
	}
	if azp != nil {
		checks |= CheckAzP
	}
	return &Validator{
		Checks:      checks,
		GracePeriod: defaultGracePeriod,
		Iss:         iss,
		Aud:         aud,
		AzP:         azp,
	}
}

// NewAccessTokenValidator returns a [Validator] configured for OAuth 2.1 JWT
// access tokens per RFC 9068 §2.2.
//
// Pass the allowed issuers and audiences, or nil to skip that check.
// Use []string{"*"} to require the claim be present without restricting its value.
//
// Checks enabled by default: iss, exp, aud, sub, client_id, iat, jti, and scope.
// requiredScopes controls scope validation:
//   - no args: scope not checked
//   - []string{}...: scope must be present (any value accepted)
//   - "openid", "profile", ...: scope must contain all listed values
//
// Not checked: nbf, auth_time, azp.
//
// https://www.rfc-editor.org/rfc/rfc9068.html#section-2.2
func NewAccessTokenValidator(iss, aud []string, requiredScopes ...string) *Validator {
	checks := ChecksConfigured | CheckSub | CheckExp | CheckIAt | CheckJTI | CheckClientID
	if iss != nil {
		checks |= CheckIss
	}
	if aud != nil {
		checks |= CheckAud
	}
	if requiredScopes != nil {
		checks |= CheckScope
	}
	return &Validator{
		Checks:         checks,
		GracePeriod:    defaultGracePeriod,
		Iss:            iss,
		Aud:            aud,
		RequiredScopes: requiredScopes,
	}
}

// Validate checks JWT claims according to the configured [Checks] bitmask.
//
// Each Check* flag enables its check. Explicit configuration
// (non-nil Iss/Aud/AzP, non-empty RequiredScopes, MaxAge > 0) forces
// the corresponding check regardless of the Checks bitmask.
//
// The individual check methods on [TokenClaims] are exported so that custom
// validators can call them directly without going through Validate.
//
// The errs parameter lets callers thread in errors from earlier checks
// (e.g. [RFCHeader.IsAllowedTyp]) so that all findings appear in a single
// joined error. Pass nil when there are no prior errors.
//
// now is caller-supplied (not time.Now()) so that validation is
// deterministic and testable.
//
// Returns nil on success. On failure, the returned error is a joined
// error that supports [errors.Is] for individual sentinels (e.g.
// [ErrAfterExp], [ErrMissingClaim]). Use Unwrap() []error to iterate
// each finding.
func (v *Validator) Validate(errs []error, claims Claims, now time.Time) error {
	tc := claims.GetTokenClaims()

	// Detect unconfigured validator: no Check* flags and no explicit config.
	if v.Checks == 0 && len(v.Iss) == 0 && len(v.Aud) == 0 && len(v.AzP) == 0 &&
		len(v.RequiredScopes) == 0 && v.MaxAge == 0 {
		return appendError(nil, ErrMisconfigured, "validator has no checks configured; use a constructor or set Check* flags")[0]
	}

	skew := resolveSkew(v.GracePeriod)

	if v.Iss != nil || v.Checks&CheckIss != 0 {
		errs = tc.IsAllowedIss(errs, v.Iss)
	}
	if v.Checks&CheckSub != 0 {
		errs = tc.IsPresentSub(errs)
	}
	if v.Aud != nil || v.Checks&CheckAud != 0 {
		errs = tc.HasAllowedAud(errs, v.Aud)
	}
	if v.Checks&CheckExp != 0 {
		errs = tc.IsBeforeExp(errs, now, skew)
	}
	if v.Checks&CheckNBf != 0 {
		errs = tc.IsAfterNBf(errs, now, skew)
	}
	if v.Checks&CheckIAt != 0 {
		errs = tc.IsAfterIAt(errs, now, skew)
	}
	if v.Checks&CheckJTI != 0 {
		errs = tc.IsPresentJTI(errs)
	}
	if v.MaxAge > 0 || v.Checks&CheckAuthTime != 0 {
		errs = tc.IsValidAuthTime(errs, now, skew, v.MaxAge)
	}
	if v.AzP != nil || v.Checks&CheckAzP != 0 {
		errs = tc.IsAllowedAzP(errs, v.AzP)
	}
	if v.Checks&CheckClientID != 0 {
		errs = tc.IsPresentClientID(errs)
	}
	if len(v.RequiredScopes) > 0 || v.Checks&CheckScope != 0 {
		errs = tc.ContainsScopes(errs, v.RequiredScopes)
	}

	if len(errs) > 0 {
		// Annotate time-related errors with the server's clock for debugging.
		serverTime := fmt.Sprintf("server time %s (%s)", now.Format("2006-01-02 15:04:05 MST"), time.Local)
		for _, e := range errs {
			if ve, ok := e.(*ValidationError); ok && isTimeSentinel(ve.Err) {
				ve.Description = fmt.Sprintf("%s; %s", ve.Description, serverTime)
			}
		}
		return errors.Join(errs...)
	}

	return nil
}

// --- Per-claim check methods on *TokenClaims ---
//
// These exported methods can be called directly by custom validators.
// Each method appends validation errors to the provided slice and returns it.
// The [Validator] decides which checks to call based on its [Checks] bitmask.
//
// Methods are named by assertion kind:
//
//   - IsAllowed   - value must appear in a configured list
//   - HasAllowed  - value must intersect a configured list
//   - IsPresent   - value must be non-empty
//   - IsBefore    - now must be before a time boundary
//   - IsAfter     - now must be after a time boundary
//   - IsValid     - composite check (presence + time bounds)
//   - Contains    - value must contain all required entries

// IsAllowedIss validates the issuer claim.
//
// Allowed semantics: nil = misconfigured (error), [] = misconfigured (error),
// ["*"] = any non-empty value, ["x","y"] = must match one.
//
// At the [Validator] level, passing nil Iss disables the issuer check
// entirely (the method is never called). Calling this method directly
// with nil is a misconfiguration error.
func (tc *TokenClaims) IsAllowedIss(errs []error, allowed []string) []error {
	if allowed == nil {
		return appendError(errs, ErrMisconfigured, "iss: issuer checking enabled but Iss is nil")
	}
	if len(allowed) == 0 {
		return appendError(errs, ErrMisconfigured, "iss: non-nil empty Iss allows no issuers")
	} else if tc.Iss == "" {
		return appendError(errs, ErrMissingClaim, "iss: missing required claim")
	} else if !slices.Contains(allowed, "*") && !slices.Contains(allowed, tc.Iss) {
		return appendError(errs, ErrInvalidClaim, "iss %q not in allowed list", tc.Iss)
	}
	return errs
}

// IsPresentSub validates that the subject claim is present.
func (tc *TokenClaims) IsPresentSub(errs []error) []error {
	if tc.Sub == "" {
		return appendError(errs, ErrMissingClaim, "sub: missing required claim")
	}
	return errs
}

// HasAllowedAud validates the audience claim.
//
// Allowed semantics: nil = misconfigured (error), [] = misconfigured (error),
// ["*"] = any non-empty value, ["x","y"] = token's aud must intersect.
//
// At the [Validator] level, passing nil Aud disables the audience check
// entirely (the method is never called). Calling this method directly
// with nil is a misconfiguration error.
func (tc *TokenClaims) HasAllowedAud(errs []error, allowed []string) []error {
	if allowed == nil {
		return appendError(errs, ErrMisconfigured, "aud: audience checking enabled but Aud is nil")
	}
	if len(allowed) == 0 {
		return appendError(errs, ErrMisconfigured, "aud: non-nil empty Aud allows no audiences")
	} else if len(tc.Aud) == 0 {
		return appendError(errs, ErrMissingClaim, "aud: missing required claim")
	} else if !slices.Contains(allowed, "*") && !slices.ContainsFunc([]string(tc.Aud), func(a string) bool {
		return slices.Contains(allowed, a)
	}) {
		return appendError(errs, ErrInvalidClaim, "aud %v not in allowed list", tc.Aud)
	}
	return errs
}

// IsBeforeExp validates the expiration claim.
// now is caller-supplied for testability; pass time.Now() in production.
func (tc *TokenClaims) IsBeforeExp(errs []error, now time.Time, skew time.Duration) []error {
	if tc.Exp <= 0 {
		return appendError(errs, ErrMissingClaim, "exp: missing required claim")
	}
	expTime := time.Unix(tc.Exp, 0)
	if now.After(expTime.Add(skew)) {
		dur := now.Sub(expTime)
		return appendError(errs, ErrAfterExp, "expired %s ago (%s)",
			formatDuration(dur), expTime.Format("2006-01-02 15:04:05 MST"))
	}
	return errs
}

// IsAfterNBf validates the not-before claim. Absence is never an error.
// now is caller-supplied for testability; pass time.Now() in production.
func (tc *TokenClaims) IsAfterNBf(errs []error, now time.Time, skew time.Duration) []error {
	if tc.NBf <= 0 {
		return errs
	}
	nbfTime := time.Unix(tc.NBf, 0)
	if nbfTime.After(now.Add(skew)) {
		dur := nbfTime.Sub(now)
		return appendError(errs, ErrBeforeNBf, "nbf is %s in the future (%s)",
			formatDuration(dur), nbfTime.Format("2006-01-02 15:04:05 MST"))
	}
	return errs
}

// IsAfterIAt validates that the issued-at claim is not in the future.
// now is caller-supplied for testability; pass time.Now() in production.
//
// Unlike iss or sub, absence is not an error - iat is optional per
// RFC 7519. However, when present, a future iat is rejected as a
// common-sense sanity check (the spec does not require this).
func (tc *TokenClaims) IsAfterIAt(errs []error, now time.Time, skew time.Duration) []error {
	if tc.IAt <= 0 {
		return errs // absence is not an error
	}
	iatTime := time.Unix(tc.IAt, 0)
	if iatTime.After(now.Add(skew)) {
		dur := iatTime.Sub(now)
		return appendError(errs, ErrBeforeIAt, "iat is %s in the future (%s)",
			formatDuration(dur), iatTime.Format("2006-01-02 15:04:05 MST"))
	}
	return errs
}

// IsPresentJTI validates that the JWT ID claim is present.
func (tc *TokenClaims) IsPresentJTI(errs []error) []error {
	if tc.JTI == "" {
		return appendError(errs, ErrMissingClaim, "jti: missing required claim")
	}
	return errs
}

// IsValidAuthTime validates the authentication time claim.
// now is caller-supplied for testability; pass time.Now() in production.
//
// When maxAge is positive, auth_time must be present and within maxAge
// of now. When maxAge is zero, only presence and future-time checks apply.
func (tc *TokenClaims) IsValidAuthTime(errs []error, now time.Time, skew time.Duration, maxAge time.Duration) []error {
	if tc.AuthTime == 0 {
		return appendError(errs, ErrMissingClaim, "auth_time: missing required claim")
	}
	authTime := time.Unix(tc.AuthTime, 0)
	authTimeStr := authTime.Format("2006-01-02 15:04:05 MST")
	if authTime.After(now.Add(skew)) {
		dur := authTime.Sub(now)
		return appendError(errs, ErrBeforeAuthTime, "auth_time %s is %s in the future",
			authTimeStr, formatDuration(dur))
	} else if maxAge > 0 {
		age := now.Sub(authTime)
		if age > maxAge+skew {
			diff := age - maxAge
			return appendError(errs, ErrAfterAuthMaxAge, "auth_time %s is %s old, exceeding max age %s by %s",
				authTimeStr, formatDuration(age), formatDuration(maxAge), formatDuration(diff))
		}
	}
	return errs
}

// IsAllowedAzP validates the authorized party claim.
//
// Allowed semantics: nil = misconfigured (error), [] = misconfigured (error),
// ["*"] = any non-empty value, ["x","y"] = must match one.
func (tc *TokenClaims) IsAllowedAzP(errs []error, allowed []string) []error {
	if allowed == nil {
		return appendError(errs, ErrMisconfigured, "azp: authorized party checking enabled but AzP is nil")
	}
	if len(allowed) == 0 {
		return appendError(errs, ErrMisconfigured, "azp: non-nil empty AzP allows no parties")
	} else if tc.AzP == "" {
		return appendError(errs, ErrMissingClaim, "azp: missing required claim")
	} else if !slices.Contains(allowed, "*") && !slices.Contains(allowed, tc.AzP) {
		return appendError(errs, ErrInvalidClaim, "azp %q not in allowed list", tc.AzP)
	}
	return errs
}

// IsPresentClientID validates that the client_id claim is present.
func (tc *TokenClaims) IsPresentClientID(errs []error) []error {
	if tc.ClientID == "" {
		return appendError(errs, ErrMissingClaim, "client_id: missing required claim")
	}
	return errs
}

// ContainsScopes validates that the token's scope claim is present and
// contains all required values. When required is nil, only presence is checked.
func (tc *TokenClaims) ContainsScopes(errs []error, required []string) []error {
	if len(tc.Scope) == 0 {
		return appendError(errs, ErrMissingClaim, "scope: missing required claim")
	}
	for _, req := range required {
		if !slices.Contains(tc.Scope, req) {
			errs = appendError(errs, ErrInsufficientScope, "scope %q not granted", req)
		}
	}
	return errs
}

// IsAllowedTyp validates that the JOSE "typ" header is one of the allowed
// values. Comparison is case-insensitive per RFC 7515 §4.1.9.
// Call this between [Verifier.Verify] and [Validator.Validate] to enforce
// token-type constraints (e.g. reject an access token where an ID token
// is expected).
//
//	hdr := jws.GetHeader()
//	errs = hdr.IsAllowedTyp(errs, []string{"JWT"})
func (h *RFCHeader) IsAllowedTyp(errs []error, allowed []string) []error {
	if len(allowed) == 0 {
		return appendError(errs, ErrMisconfigured, "typ: allowed list is empty")
	}
	for _, a := range allowed {
		if strings.EqualFold(h.Typ, a) {
			return errs
		}
	}
	return appendError(errs, ErrInvalidTyp, "typ %q not in allowed list", h.Typ)
}
