package csvauth

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestCredentialCreationAndVerification(t *testing.T) {
	type testCase struct {
		purpose       string
		name          string
		params        []string
		roles         []string
		extra         string
		isLogin       bool
		isRecoverable bool
	}

	tests := []testCase{
		{"service1", "acme", []string{"aes-128-gcm"}, nil, "token1", false, true},
		{"service2", "acme", []string{"plain"}, nil, "token2", false, true},
		{"service3", "user3", []string{"pbkdf2", "1000", "16", "SHA-256"}, nil, "token3", false, false},
		{"service4", "user4", []string{"bcrypt"}, []string{"audit", "triage"}, "token4", false, false},
		{"login", "user1", []string{"pbkdf2", "1000", "16", "SHA-256"}, nil, "pass1", true, false},
		{"login", "user2", []string{"bcrypt"}, nil, "pass2", true, false},
		{"login", "user3", []string{"aes-128-gcm"}, nil, "pass3", true, true},
		{"login", "user4", []string{"plain"}, nil, "pass4", true, true},
	}

	for _, tc := range tests {
		t.Run(fmt.Sprintf("%s/%s", tc.purpose, tc.name), func(t *testing.T) {
			var key [16]byte
			a := &Auth{
				aes128key:       key,
				credentials:     make(map[Name]Credential),
				serviceAccounts: make(map[Purpose]Credential),
			}
			secret := tc.extra
			c := a.NewCredential(tc.purpose, tc.name, secret, tc.params, tc.roles, tc.extra)
			if c == nil {
				t.Fatal("NewCredential returned nil")
			}
			if tc.isLogin {
				_ = a.CacheCredential(*c)
			} else {
				_ = a.CacheServiceAccount(*c)
			}
			record := c.ToRecord()

			// Verify record format
			if record[0] != tc.purpose {
				t.Errorf("purpose mismatch: got %q want %q", record[0], tc.purpose)
			}
			if record[1] != tc.name {
				t.Errorf("name mismatch: got %q want %q", record[1], tc.name)
			}
			if record[2] != strings.Join(tc.params, " ") {
				t.Errorf("params mismatch: got %q want %q", record[2], strings.Join(tc.params, " "))
			}
			salt64 := record[3]
			derived64 := record[4]
			algo := tc.params[0]
			switch algo {
			case "plain":
				if salt64 != "" {
					t.Errorf("plain salt should be empty, got %q", salt64)
				}
				if derived64 != secret {
					t.Errorf("plain derived mismatch: got %q want %q", derived64, secret)
				}
			case "aes-128-gcm":
				saltb, err := base64.RawURLEncoding.DecodeString(salt64)
				if err != nil || len(saltb) != 12 {
					t.Errorf("gcm salt invalid: len %d err %v", len(saltb), err)
				}
				derivedb, err := base64.RawURLEncoding.DecodeString(derived64)
				if err != nil {
					t.Errorf("gcm derived %q invalid: err %v", derivedb, err)
				}
			case "pbkdf2":
				saltb, err := base64.RawURLEncoding.DecodeString(salt64)
				if err != nil || len(saltb) != 16 {
					t.Errorf("pbkdf2 salt invalid: len %d err %v", len(saltb), err)
				}
				derivedb, err := base64.RawURLEncoding.DecodeString(derived64)
				if err != nil || len(derivedb) != 16 {
					t.Errorf("pbkdf2 derived invalid: len %d err %v", len(derivedb), err)
				}
			case "bcrypt":
				if salt64 != "" {
					t.Errorf("bcrypt salt should be empty, got %q", salt64)
				}
				if !strings.HasPrefix(derived64, "$2a$12$") {
					t.Errorf("bcrypt derived invalid: got %q", derived64)
				}
			}
			if len(tc.roles) > 0 && record[5] != strings.Join(tc.roles, " ") {
				t.Errorf("roles mismatch: got %q want %q", record[5], strings.Join(tc.roles, " "))
			}
			if len(tc.extra) > 0 && record[6] != tc.extra {
				t.Errorf("extra mismatch: got %q want %q", record[6], tc.extra)
			}

			// Verify functionality
			var c2 Credential
			var err error
			if tc.isLogin {
				if err := a.Verify(tc.name, secret); err != nil {
					t.Errorf("Auth.Verify failed for %s %s with %s: %v", tc.purpose, tc.name, secret, err)
				}
				c2, err = a.LoadCredential(tc.name)
				if err != nil {
					t.Errorf("LoadCredential failed for %s %s: %v", tc.purpose, tc.name, err)
				}
			} else {
				c2, err = a.LoadServiceAccount(tc.purpose)
				if err != nil {
					t.Errorf("LoadServiceAccount failed for %s %s: %v", tc.purpose, tc.name, err)
				}
			}

			if tc.isRecoverable {
				if c2.Secret() != secret {
					t.Errorf("Secret mismatch: got %q want %q", c2.Secret(), secret)
				}
			} else {
				if c2.Secret() != "" {
					t.Errorf("Secret should be empty for hashed service account, got %q", c2.Secret())
				}
			}

			if err := c2.Verify(tc.name, secret); err != nil {
				t.Errorf("Auth.Verify failed for %s: %v", tc.name, err)
			}
			if err := c2.Verify(tc.name, ""); err == nil {
				t.Errorf("Auth.Verify incorrectly passed an empty password for %s %s", tc.purpose, tc.name)
			}
			if err := c2.Verify(tc.name, "wrong"); err == nil {
				t.Errorf("Auth.Verify incorrectly passed a wrong password for %s %s", tc.purpose, tc.name)
			}
		})
	}
}
