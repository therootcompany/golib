package rfc_test

import (
	"errors"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/jwt"

	rfc "github.com/therootcompany/golib/auth/jwt/examples/rfc-claims"
)

// TestNewRFCValidator shows how to use [rfc.NewRFCValidator] to build
// a permissive [jwt.Validator] that checks only exp, iat, and nbf,
// then opt in to additional checks by OR-ing more flags.
func TestNewRFCValidator(t *testing.T) {
	now := time.Now()

	claims := jwt.TokenClaims{
		Iss: "https://example.com",
		Aud: jwt.Listish{"myapp"},
		Exp: now.Add(time.Hour).Unix(),
		IAt: now.Unix(),
	}

	v := rfc.NewRFCValidator(
		[]string{"https://example.com"},
		[]string{"myapp"},
	)

	if err := v.Validate(nil, &claims, now); err != nil {
		t.Fatalf("NewRFCValidator rejected valid claims: %v", err)
	}

	// Opt in to sub checking by adding the flag.
	v.Checks |= jwt.CheckSub
	if err := v.Validate(nil, &claims, now); !errors.Is(err, jwt.ErrMissingClaim) {
		t.Fatalf("expected ErrMissingClaim for missing sub, got: %v", err)
	}

	// Expired token must be rejected.
	expired := claims
	expired.Exp = now.Add(-time.Hour).Unix()
	v.Checks &^= jwt.CheckSub // remove sub check for this test
	if err := v.Validate(nil, &expired, now); !errors.Is(err, jwt.ErrAfterExp) {
		t.Fatalf("expected ErrAfterExp, got: %v", err)
	}
}

// TestDirectCheckMethods shows how to call the individual check methods on
// [jwt.TokenClaims] directly, without using a [jwt.Validator] at all.
// This is useful for one-off validations or building a fully custom validator.
func TestDirectCheckMethods(t *testing.T) {
	now := time.Now()
	skew := 2 * time.Second

	claims := jwt.TokenClaims{
		Iss: "https://example.com",
		Aud: jwt.Listish{"myapp"},
		Exp: now.Add(time.Hour).Unix(),
		IAt: now.Unix(),
	}

	// Call individual check methods - each appends errors to the slice.
	var errs []error
	errs = claims.IsAllowedIss(errs, []string{"https://example.com"})
	errs = claims.HasAllowedAud(errs, []string{"myapp"})
	errs = claims.IsBeforeExp(errs, now, skew)
	errs = claims.IsAfterIAt(errs, now, skew)

	// No errors when all checks pass.
	if err := errors.Join(errs...); err != nil {
		t.Fatalf("direct checks rejected valid claims: %v", err)
	}

	// Now validate a bad token the same way.
	bad := jwt.TokenClaims{
		Iss: "https://evil.com",
		Exp: now.Add(-time.Hour).Unix(),
	}

	var badErrs []error
	badErrs = bad.IsAllowedIss(badErrs, []string{"https://example.com"})
	badErrs = bad.IsBeforeExp(badErrs, now, skew)

	err := errors.Join(badErrs...)
	if err == nil {
		t.Fatal("expected errors from bad claims")
	}
	if !errors.Is(err, jwt.ErrInvalidClaim) {
		t.Fatalf("expected ErrInvalidClaim for bad iss, got: %v", err)
	}
	if !errors.Is(err, jwt.ErrAfterExp) {
		t.Fatalf("expected ErrAfterExp for expired token, got: %v", err)
	}
}
