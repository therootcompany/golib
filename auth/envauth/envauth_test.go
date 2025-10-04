package envauth

import (
	"crypto/pbkdf2"
	"crypto/sha256"
	"testing"
)

var salt = []byte("buzzword")

func TestBasicCredentials_Verify(t *testing.T) {
	tests := []struct {
		name     string
		creds    BasicCredentials
		username string
		password string
		want     bool
	}{
		{
			name:     "empty username, correct password",
			creds:    BasicCredentials{Username: "", Password: "secret"},
			username: "",
			password: "secret",
			want:     true,
		},
		{
			name:     "correct username, correct password",
			creds:    BasicCredentials{Username: "user", Password: "secret"},
			username: "user",
			password: "secret",
			want:     true,
		},
		{
			name:     "incorrect username, correct password",
			creds:    BasicCredentials{Username: "user", Password: "secret"},
			username: "wrong",
			password: "secret",
			want:     false,
		},
		{
			name:     "correct username, incorrect password",
			creds:    BasicCredentials{Username: "user", Password: "secret"},
			username: "user",
			password: "wrong",
			want:     false,
		},
		{
			name:     "correct username, empty password",
			creds:    BasicCredentials{Username: "user", Password: "secret"},
			username: "user",
			password: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.creds.Verify(tt.username, tt.password)
			if got != tt.want {
				t.Errorf("Verify(%q, %q) = %v; want %v", tt.username, tt.password, got, tt.want)
			}
		})
	}
}

func TestPBKDF2Credentials_Verify(t *testing.T) {
	secretDigest, err := pbkdf2.Key(sha256.New, "secret", salt, 1000, 16)
	if err != nil {
		t.Errorf("pbkdf2.Key(sha256.New, \"secret\", salt, 1000, 16) = %v", err)
	}
	emptyDigest, err := pbkdf2.Key(sha256.New, "", salt, 1000, 16)
	if err != nil {
		t.Errorf("pbkdf2.Key(sha256.New, \"\", salt, 1000, 16) = %v", err)
	}

	tests := []struct {
		name     string
		creds    PBKDF2Credentials
		username string
		password string
		want     bool
	}{
		{
			name:     "empty username, correct password",
			creds:    PBKDF2Credentials{Username: "", DerivedKey: secretDigest, Salt: salt, Iterations: 1000},
			username: "",
			password: "secret",
			want:     true,
		},
		{
			name:     "correct username, correct password",
			creds:    PBKDF2Credentials{Username: "user", DerivedKey: secretDigest, Salt: salt, Iterations: 1000},
			username: "user",
			password: "secret",
			want:     true,
		},
		{
			name:     "incorrect username, correct password",
			creds:    PBKDF2Credentials{Username: "user", DerivedKey: secretDigest, Salt: salt, Iterations: 1000},
			username: "wrong",
			password: "secret",
			want:     false,
		},
		{
			name:     "correct username, incorrect password",
			creds:    PBKDF2Credentials{Username: "user", DerivedKey: secretDigest, Salt: salt, Iterations: 1000},
			username: "user",
			password: "wrong",
			want:     false,
		},
		{
			name:     "correct username, empty password",
			creds:    PBKDF2Credentials{Username: "user", DerivedKey: secretDigest, Salt: salt, Iterations: 1000},
			username: "user",
			password: "",
			want:     false,
		},
		{
			name:     "empty username, empty pre-computed digest",
			creds:    PBKDF2Credentials{Username: "", DerivedKey: emptyDigest, Salt: salt, Iterations: 1000},
			username: "",
			password: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.creds.Verify(tt.username, tt.password)
			if got != tt.want {
				t.Errorf("Verify(%q, %q) = %v; want %v", tt.username, tt.password, got, tt.want)
			}
		})
	}
}
