package rfc_test

import (
	"errors"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/jwt"

	rfc "github.com/therootcompany/golib/auth/jwt/examples/rfc-claims"
)

// TestRFCValidator confirms that RFCValidator always checks exp/iat, checks
// iss/aud/azp when configured, and skips sub/jti/auth_time/amr by default.
func TestRFCValidator(t *testing.T) {
	now := time.Now()

	// Minimal claims: only the fields RFCValidator checks by default.
	minimal := jwt.IDTokenClaims{
		Iss: "https://example.com",
		Aud: jwt.Audience{"myapp"},
		Exp: now.Add(time.Hour).Unix(),
		Iat: now.Unix(),
		// Sub, JTI, AuthTime, AMR, Azp intentionally absent
	}

	v := &rfc.RFCValidator{
		Iss: []string{"https://example.com"},
		Aud: []string{"myapp"},
	}

	if _, err := v.Validate(&minimal, now); err != nil {
		t.Fatalf("RFCValidator rejected minimal valid claims: %v", err)
	}

	// Expired token must still be rejected.
	expired := minimal
	expired.Exp = now.Add(-time.Hour).Unix()
	if _, err := v.Validate(&expired, now); !errors.Is(err, jwt.ErrAfterExp) {
		t.Fatalf("expected ErrAfterExp, got: %v", err)
	}

	// Future iat must be rejected.
	futureIat := minimal
	futureIat.Iat = now.Add(time.Hour).Unix()
	if _, err := v.Validate(&futureIat, now); !errors.Is(err, jwt.ErrBeforeIat) {
		t.Fatalf("expected ErrBeforeIat, got: %v", err)
	}
}
