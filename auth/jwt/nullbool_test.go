package jwt_test

import (
	"encoding/json"
	"testing"

	"github.com/therootcompany/golib/auth/jwt"
)

func TestNullBool_MarshalJSON(t *testing.T) {
	tests := []struct {
		name string
		nb   jwt.NullBool
		want string
	}{
		{"true", jwt.NullBool{Bool: true, Valid: true}, "true"},
		{"false", jwt.NullBool{Bool: false, Valid: true}, "false"},
		{"null (zero value)", jwt.NullBool{}, "null"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := json.Marshal(tt.nb)
			if err != nil {
				t.Fatalf("Marshal error: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("Marshal = %s, want %s", got, tt.want)
			}
		})
	}
}

func TestNullBool_UnmarshalJSON(t *testing.T) {
	tests := []struct {
		name      string
		input     string
		wantValue bool
		wantValid bool
	}{
		{"true", "true", true, true},
		{"false", "false", false, true},
		{"null", "null", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var nb jwt.NullBool
			if err := json.Unmarshal([]byte(tt.input), &nb); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}
			if nb.Bool != tt.wantValue {
				t.Errorf("Value = %v, want %v", nb.Bool, tt.wantValue)
			}
			if nb.Valid != tt.wantValid {
				t.Errorf("Valid = %v, want %v", nb.Valid, tt.wantValid)
			}
		})
	}
}

func TestNullBool_UnmarshalJSON_InvalidInput(t *testing.T) {
	var nb jwt.NullBool
	if err := json.Unmarshal([]byte(`"yes"`), &nb); err == nil {
		t.Error("expected error for invalid input, got nil")
	}
}

func TestNullBool_IsZero(t *testing.T) {
	tests := []struct {
		name string
		nb   jwt.NullBool
		want bool
	}{
		{"zero value", jwt.NullBool{}, true},
		{"true", jwt.NullBool{Bool: true, Valid: true}, false},
		{"false", jwt.NullBool{Bool: false, Valid: true}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.nb.IsZero(); got != tt.want {
				t.Errorf("IsZero() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestNullBool_RoundTrip(t *testing.T) {
	values := []jwt.NullBool{
		{Bool: true, Valid: true},
		{Bool: false, Valid: true},
		{Bool: false, Valid: false},
	}
	for _, orig := range values {
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var got jwt.NullBool
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if got.Bool != orig.Bool || got.Valid != orig.Valid {
			t.Errorf("round-trip: got {%v, %v}, want {%v, %v}",
				got.Bool, got.Valid, orig.Bool, orig.Valid)
		}
	}
}

func TestNullBool_ClaimsIntegration(t *testing.T) {
	t.Run("marshal with email verified true", func(t *testing.T) {
		claims := jwt.StandardClaims{
			TokenClaims: jwt.TokenClaims{
				Iss: "https://example.com",
				Sub: "user123",
				Exp: 9999999999,
				IAt: 1000000000,
			},
			Email:         "user@example.com",
			EmailVerified: jwt.NullBool{Bool: true, Valid: true},
		}
		data, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if string(raw["email_verified"]) != "true" {
			t.Errorf("email_verified = %s, want true", raw["email_verified"])
		}
	})

	t.Run("marshal with email verified false", func(t *testing.T) {
		claims := jwt.StandardClaims{
			TokenClaims: jwt.TokenClaims{
				Iss: "https://example.com",
				Sub: "user123",
				Exp: 9999999999,
				IAt: 1000000000,
			},
			Email:         "user@example.com",
			EmailVerified: jwt.NullBool{Bool: false, Valid: true},
		}
		data, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if string(raw["email_verified"]) != "false" {
			t.Errorf("email_verified = %s, want false", raw["email_verified"])
		}
	})

	t.Run("marshal omits verified when no email", func(t *testing.T) {
		claims := jwt.StandardClaims{
			TokenClaims: jwt.TokenClaims{
				Iss: "https://example.com",
				Sub: "user123",
				Exp: 9999999999,
				IAt: 1000000000,
			},
			// No email, no EmailVerified -> field omitted via omitzero
		}
		data, err := json.Marshal(claims)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}

		var raw map[string]json.RawMessage
		if err := json.Unmarshal(data, &raw); err != nil {
			t.Fatal(err)
		}
		if _, ok := raw["email_verified"]; ok {
			t.Errorf("email_verified present = %s, want omitted", raw["email_verified"])
		}
		if _, ok := raw["phone_number_verified"]; ok {
			t.Errorf("phone_number_verified present = %s, want omitted", raw["phone_number_verified"])
		}
	})

	t.Run("unmarshal claims with verified fields", func(t *testing.T) {
		input := `{
			"iss": "https://example.com",
			"sub": "user123",
			"exp": 9999999999,
			"iat": 1000000000,
			"email": "user@example.com",
			"email_verified": true,
			"phone_number": "+1555000000",
			"phone_number_verified": false
		}`
		var claims jwt.StandardClaims
		if err := json.Unmarshal([]byte(input), &claims); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if !claims.EmailVerified.Valid || !claims.EmailVerified.Bool {
			t.Errorf("EmailVerified = {%v, %v}, want {true, true}",
				claims.EmailVerified.Bool, claims.EmailVerified.Valid)
		}
		if !claims.PhoneNumberVerified.Valid || claims.PhoneNumberVerified.Bool {
			t.Errorf("PhoneNumberVerified = {%v, %v}, want {false, true}",
				claims.PhoneNumberVerified.Bool, claims.PhoneNumberVerified.Valid)
		}
	})

	t.Run("unmarshal claims with null verified fields", func(t *testing.T) {
		input := `{
			"iss": "https://example.com",
			"sub": "user123",
			"exp": 9999999999,
			"iat": 1000000000,
			"email_verified": null,
			"phone_number_verified": null
		}`
		var claims jwt.StandardClaims
		if err := json.Unmarshal([]byte(input), &claims); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if claims.EmailVerified.Valid {
			t.Error("EmailVerified.Valid = true, want false")
		}
		if claims.PhoneNumberVerified.Valid {
			t.Error("PhoneNumberVerified.Valid = true, want false")
		}
	})

	t.Run("unmarshal claims with omitted verified fields", func(t *testing.T) {
		input := `{
			"iss": "https://example.com",
			"sub": "user123",
			"exp": 9999999999,
			"iat": 1000000000
		}`
		var claims jwt.StandardClaims
		if err := json.Unmarshal([]byte(input), &claims); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		// Omitted fields -> zero value: {false, false}
		if claims.EmailVerified.Valid {
			t.Error("EmailVerified.Valid = true, want false")
		}
		if claims.PhoneNumberVerified.Valid {
			t.Error("PhoneNumberVerified.Valid = true, want false")
		}
	})

	t.Run("round-trip claims", func(t *testing.T) {
		orig := jwt.StandardClaims{
			TokenClaims: jwt.TokenClaims{
				Iss: "https://example.com",
				Sub: "user123",
				Exp: 9999999999,
				IAt: 1000000000,
			},
			Email:               "user@example.com",
			EmailVerified:       jwt.NullBool{Bool: true, Valid: true},
			PhoneNumber:         "+1555000000",
			PhoneNumberVerified: jwt.NullBool{Bool: false, Valid: true},
		}
		data, err := json.Marshal(orig)
		if err != nil {
			t.Fatalf("Marshal error: %v", err)
		}
		var got jwt.StandardClaims
		if err := json.Unmarshal(data, &got); err != nil {
			t.Fatalf("Unmarshal error: %v", err)
		}
		if got.EmailVerified != orig.EmailVerified {
			t.Errorf("EmailVerified = %+v, want %+v", got.EmailVerified, orig.EmailVerified)
		}
		if got.PhoneNumberVerified != orig.PhoneNumberVerified {
			t.Errorf("PhoneNumberVerified = %+v, want %+v", got.PhoneNumberVerified, orig.PhoneNumberVerified)
		}
	})
}
