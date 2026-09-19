package expresscookie_test

import (
	"crypto/rand"
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
	cookie := expresscookie.BuildSignedCookie(expresscookie.SessionCookie{
		Name:      "session",
		Path:      "/",
		Payload:   []byte(`{"sub":"user-1","exp":123}`),
		ExpiresAt: expiresAt,
	}, secret)
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode {
		t.Fatalf("cookie security attributes = %#v", cookie)
	}
	payload, err := expresscookie.VerifySignedCookie(cookie.Value, secret)
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) != `{"sub":"user-1","exp":123}` {
		t.Fatalf("payload = %q", payload)
	}
}

func TestSignedCookieRejectsTampering(t *testing.T) {
	secret := testSecret(t)
	cookie := expresscookie.BuildSignedCookie(expresscookie.SessionCookie{
		Name:      "session",
		Payload:   []byte("payload"),
		ExpiresAt: time.Now().Add(time.Hour),
	}, secret)
	if _, err := expresscookie.VerifySignedCookie(cookie.Value+"tampered", secret); err == nil {
		t.Fatal("tampered cookie was accepted")
	}
}

func TestCookieSignatureCompatibility(t *testing.T) {
	const payload = "hello world"
	secret, err := expresscookie.NewSecret([]byte("node-session-secret"))
	if err != nil {
		t.Fatal(err)
	}
	const want = "s%3Ahello+world.mkIi5KNNlov4yomWFLlq8430i8d4SRNbvScYrM6F5jk"
	if got := expresscookie.EncodeSignedValue(payload, expresscookie.SignValue(payload, secret)); got != want {
		t.Fatalf("signed cookie = %q, want %q", got, want)
	}
}

func TestEncodedPayloadStages(t *testing.T) {
	secret, err := expresscookie.NewSecret([]byte("example-secret-16"))
	if err != nil {
		t.Fatal(err)
	}
	cookie := expresscookie.BuildSignedCookie(expresscookie.SessionCookie{
		Payload: []byte("SGVsbG8sIFdvcmxkIQ=="),
	}, secret)
	const want = "s%3ASGVsbG8sIFdvcmxkIQ%3D%3D.F%2FbW1t2GXhUIqykISYbB%2BFMA3lLquegPU4jYjVLsnXs"
	if cookie.Value != want {
		t.Fatalf("cookie value = %q, want %q", cookie.Value, want)
	}
}

func ExampleBuildSignedCookie() {
	secret, err := expresscookie.NewSecret([]byte("example-secret-16"))
	if err != nil {
		panic(err)
	}
	cookie := expresscookie.BuildSignedCookie(expresscookie.SessionCookie{
		Name:    "session",
		Payload: []byte("SGVsbG8sIFdvcmxkIQ=="),
	}, secret)

	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.AddCookie(cookie)
	requestCookie, err := r.Cookie("session")
	if err != nil {
		panic(err)
	}
	payload, err := expresscookie.VerifySignedCookie(requestCookie.Value, secret)
	if err != nil {
		panic(err)
	}
	fmt.Println(string(payload))
	// Output: SGVsbG8sIFdvcmxkIQ==
}
