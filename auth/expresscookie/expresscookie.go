// Package expresscookie is a general-purpose secure-cookie package for web
// applications. Payload bytes are signed as supplied, then the signed value is
// URL-escaped for cookie transport. The format is compatible with the Node.js
// npm cookie-signature package used by Express session middleware.
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
	"time"
)

const minSecretBytes = 16

var (
	// ErrNoSecret indicates that no signing secret was provided.
	ErrNoSecret = errors.New("no secret")
	// ErrSecretTooShort indicates that a secret has too little entropy.
	ErrSecretTooShort = errors.New("secret too short")
)

// Secret is a validated cookie-signing secret.
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

// SessionCookie is a signed session cookie configuration.
type SessionCookie struct {
	Name   string
	Secret Secret
	Path   string
	Domain string
	// Payload is the raw application payload to sign. It is not encoded by this
	// package; encode structured data first, such as with json.Marshal.
	Payload   []byte
	ExpiresAt time.Time
	SameSite  http.SameSite
}

// BuildSignedCookie builds an HttpOnly, Secure, SameSite=Strict cookie.
func BuildSignedCookie(c SessionCookie) *http.Cookie {
	sig := SignValue(string(c.Payload), c.Secret)
	if c.SameSite == 0 {
		c.SameSite = http.SameSiteStrictMode
	}
	signed := EncodeSignedValue(string(c.Payload), sig)
	maxAge := int(time.Until(c.ExpiresAt).Seconds())
	if maxAge < 1 {
		maxAge = 0
	}
	return &http.Cookie{
		Name:     c.Name,
		Value:    signed,
		Path:     c.Path,
		Domain:   c.Domain,
		Expires:  c.ExpiresAt,
		MaxAge:   maxAge,
		HttpOnly: true,
		Secure:   true,
		SameSite: c.SameSite,
	}
}

// VerifySignedCookie verifies a signed cookie and returns its raw payload.
func VerifySignedCookie(rawValue string, secret Secret) ([]byte, error) {
	cookieVal, err := url.QueryUnescape(rawValue)
	if err != nil {
		return nil, fmt.Errorf("failed to unescape cookie value: %w", err)
	}
	payload, sig, err := DecodeSignedValue(cookieVal)
	if err != nil {
		return nil, fmt.Errorf("failed to decode signed cookie: %w", err)
	}
	if err := VerifyHMAC(payload, sig, secret); err != nil {
		return nil, fmt.Errorf("cookie HMAC verification failed: %w", err)
	}
	return []byte(payload), nil
}

// EncodeSignedValue returns a cookie-signature-compatible signed cookie value.
func EncodeSignedValue(value, sig string) string {
	return url.QueryEscape("s:" + value + "." + sig)
}

// SignValue returns the cookie-signature-compatible HMAC-SHA256 signature.
func SignValue(value string, secret Secret) string {
	if len(secret) == 0 {
		panic(ErrNoSecret)
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(value))
	return base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
}

// DecodeSignedValue splits an Express signed cookie value.
func DecodeSignedValue(signed string) (string, string, error) {
	if len(signed) < 2 || signed[:2] != "s:" {
		return "", "", fmt.Errorf("missing 's:' prefix")
	}
	withoutPrefix := signed[2:]
	dotIdx := strings.LastIndex(withoutPrefix, ".")
	if dotIdx == -1 {
		return "", "", fmt.Errorf("missing '.' separator")
	}
	return withoutPrefix[:dotIdx], withoutPrefix[dotIdx+1:], nil
}

// VerifyHMAC verifies a cookie-signature-compatible signature.
func VerifyHMAC(payload, signature string, secret Secret) error {
	if len(secret) == 0 {
		return ErrNoSecret
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	expected := base64.RawStdEncoding.EncodeToString(mac.Sum(nil))
	normalized := strings.NewReplacer("-", "+", "_", "/").Replace(signature)
	if !hmac.Equal([]byte(expected), []byte(normalized)) {
		return fmt.Errorf("signature mismatch")
	}
	return nil
}
