package expresscookie_test

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/therootcompany/golib/auth/expresscookie"
)

func testSecret(t *testing.T) expresscookie.Secret {
	t.Helper()
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		t.Fatal(err)
	}
	validated, err := expresscookie.NewSecret(secret)
	if err != nil {
		t.Fatal(err)
	}
	return validated
}

func TestNewSecretValidation(t *testing.T) {
	tests := []struct {
		name  string
		value []byte
		want  error
	}{
		{name: "empty", want: expresscookie.ErrNoSecret},
		{name: "short", value: make([]byte, 15), want: expresscookie.ErrSecretTooShort},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			_, err := expresscookie.NewSecret(test.value)
			if err == nil {
				t.Fatal("NewSecret succeeded")
			}
			if !errors.Is(err, test.want) {
				t.Fatalf("error = %v, want %v", err, test.want)
			}
		})
	}
}

func TestNewRejectsEmptyName(t *testing.T) {
	if _, err := expresscookie.New("", nil, http.Cookie{}); !errors.Is(err, expresscookie.ErrCookieNameEmpty) {
		t.Fatalf("error = %v, want ErrCookieNameEmpty", err)
	}
}

func TestDecodeHexSecret(t *testing.T) {
	// APP_SECRET is hex, not base64.
	encoded := "0102030405060708090a0b0c0d0e0f10"
	decoded, err := expresscookie.DecodeHexSecret(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 16 || decoded[0] != 1 || decoded[15] != 16 {
		t.Fatalf("decoded secret = %x", decoded)
	}
}

func TestSignedCookieRoundTrip(t *testing.T) {
	secret := testSecret(t)
	expiresAt := time.Now().Add(time.Hour)
	cookieConfig, err := expresscookie.New("session", []byte(`{"sub":"user-1","exp":123}`), http.Cookie{
		Name:    "session",
		Path:    "/",
		Expires: expiresAt,
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookieConfig.Sign(secret)
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie security attributes = %#v", cookie)
	}
	parsed, err := expresscookie.Parse(cookie.Value)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parsed.Verify(secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"sub":"user-1","exp":123}` {
		t.Fatalf("payload = %q", payload)
	}
}

func TestSignedCookieRejectsTampering(t *testing.T) {
	secret := testSecret(t)
	cookieConfig, err := expresscookie.New("session", []byte("payload"), http.Cookie{
		Name:    "session",
		Expires: time.Now().Add(time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookieConfig.Sign(secret)
	parsed, err := expresscookie.Parse(cookie.Value + "tampered")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := parsed.Verify(secret)
	if err == nil {
		t.Fatal("tampered cookie was accepted")
	}
	if string(payload) != "payload" {
		t.Fatalf("payload = %q, want %q", payload, "payload")
	}
}

func TestEncodedPayloadStages(t *testing.T) {
	secret, err := expresscookie.NewSecret([]byte("example-secret-16"))
	if err != nil {
		t.Fatal(err)
	}
	cookieConfig, err := expresscookie.New("session", []byte("SGVsbG8sIFdvcmxkIQ=="), http.Cookie{})
	if err != nil {
		t.Fatal(err)
	}
	cookie := cookieConfig.Sign(secret)
	const want = "s%3ASGVsbG8sIFdvcmxkIQ%3D%3D.F%2FbW1t2GXhUIqykISYbB%2BFMA3lLquegPU4jYjVLsnXs"
	if cookie.Value != want {
		t.Fatalf("cookie value = %q, want %q", cookie.Value, want)
	}
}

func ExampleNew() {
	secret, err := expresscookie.NewSecret([]byte("example-secret-16"))
	if err != nil {
		panic(err)
	}
	payload := base64.StdEncoding.AppendEncode(nil, []byte("Hello, World!"))
	cookieConfig, err := expresscookie.New("session", payload, http.Cookie{})
	if err != nil {
		panic(err)
	}
	cookie := cookieConfig.Sign(secret)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(&cookie.Cookie)
	requestCookie, err := r.Cookie("session")
	if err != nil {
		panic(err)
	}
	parsed, err := expresscookie.Parse(requestCookie.Value)
	if err != nil {
		panic(err)
	}
	verified, err := parsed.Verify(secret)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(verified))
	// Output: SGVsbG8sIFdvcmxkIQ==
}
