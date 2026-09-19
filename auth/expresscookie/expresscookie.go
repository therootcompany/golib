package expresscookie

import (
	"bytes"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

const minSecretBytes = 16

var (
	// ErrNoSecret indicates that no signing secret was provided.
	ErrNoSecret = errors.New("no secret")
	// ErrSecretTooShort indicates that a secret has too little entropy.
	ErrSecretTooShort = errors.New("secret too short")
	// ErrCookieNameEmpty indicates that no cookie name was provided.
	ErrCookieNameEmpty = errors.New("cookie name is empty")
)

// Secret is a validated cookie-signing secret.
//
// [NewSecret] is the supported constructor. Converting bytes directly, as in
// Secret(value), bypasses validation and is unsafe for production. Direct
// conversion is retained only for security research and testing; its semantics
// may change, so callers and applications must not depend on it.
type Secret []byte

// NewSecret validates and copies a cookie-signing secret.
//
// Secrets must contain at least 16 bytes. Use a randomly generated secret of
// at least 32 bytes for new applications.
func NewSecret(value []byte) (Secret, error) {
	if len(value) == 0 {
		return nil, ErrNoSecret
	}
	if len(value) < minSecretBytes {
		return nil, fmt.Errorf("%w: got %d bytes, need at least %d", ErrSecretTooShort, len(value), minSecretBytes)
	}
	return Secret(bytes.Clone(value)), nil
}

// DecodeHexSecret decodes and validates an APP_SECRET-style hexadecimal cookie key.
func DecodeHexSecret(value string) (Secret, error) {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, ErrNoSecret
	}
	secret, err := hex.DecodeString(value)
	if err != nil {
		return nil, fmt.Errorf("decode hex secret: %w", err)
	}
	return NewSecret(secret)
}

// Cookie is a parsed or signable cookie.
//
// A parsed Cookie is untrusted until Verify succeeds. Verify returns the
// payload even when verification fails; callers must always check its error.
type Cookie struct {
	http.Cookie
	payload   []byte
	signature string
}

// New creates a signable cookie from a name, raw payload, and HTTP cookie
// options. The options' Name and Value fields are ignored. It returns
// [ErrCookieNameEmpty] when name is empty.
func New(name string, payload []byte, options http.Cookie) (Cookie, error) {
	if name == "" {
		return Cookie{}, ErrCookieNameEmpty
	}
	options.Name = name
	return Cookie{Cookie: options, payload: bytes.Clone(payload)}, nil
}

// Sign creates an HttpOnly, Secure, SameSite=Strict HTTP cookie.
func (c Cookie) Sign(secret Secret) Cookie {
	if len(secret) == 0 {
		panic(ErrNoSecret)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(c.payload)
	sig := base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
	c.Cookie.Value = url.QueryEscape("s:" + string(c.payload) + "." + sig)
	c.Cookie.HttpOnly = true
	c.Cookie.Secure = true
	if c.Cookie.SameSite == 0 {
		c.Cookie.SameSite = http.SameSiteStrictMode
	}
	return c
}

// Parse parses the signed value from an HTTP cookie without verifying it.
func Parse(rawValue string) (Cookie, error) {
	cookieValue, err := url.QueryUnescape(rawValue)
	if err != nil {
		return Cookie{}, fmt.Errorf("failed to unescape cookie value: %w", err)
	}
	if len(cookieValue) < 2 || cookieValue[:2] != "s:" {
		return Cookie{}, fmt.Errorf("failed to decode signed cookie: missing 's:' prefix")
	}
	withoutPrefix := cookieValue[2:]
	dotIdx := strings.LastIndex(withoutPrefix, ".")
	if dotIdx == -1 {
		return Cookie{}, fmt.Errorf("failed to decode signed cookie: missing '.' separator")
	}
	return Cookie{
		Cookie:    http.Cookie{Value: rawValue},
		payload:   []byte(withoutPrefix[:dotIdx]),
		signature: withoutPrefix[dotIdx+1:],
	}, nil
}

// Verify checks the signature and returns the raw payload.
//
// The payload is returned even when verification fails. Callers must always
// check the error before using it.
func (c Cookie) Verify(secret Secret) ([]byte, error) {
	payload := bytes.Clone(c.payload)
	if len(secret) == 0 {
		return payload, fmt.Errorf("cookie HMAC verification failed: %w", ErrNoSecret)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write(payload)
	expected := base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
	normalized := strings.NewReplacer("-", "+", "_", "/").Replace(c.signature)
	if !hmac.Equal([]byte(expected), []byte(normalized)) {
		return payload, fmt.Errorf("cookie HMAC verification failed: signature mismatch")
	}
	return payload, nil
}
