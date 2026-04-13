package xhubsig

import (
	"crypto/hmac"
	"encoding/hex"
	"errors"
)

var (
	ErrMissingSignature = errors.New("missing signature")
	ErrInvalidSignature = errors.New("invalid signature")
	ErrBodyTooLarge     = errors.New("body too large")
)

func Sign(h Hash, secret string, body []byte) string {
	mac := hmac.New(h.New, []byte(secret))
	mac.Write(body)
	return h.Prefix + hex.EncodeToString(mac.Sum(nil))
}

func Verify(h Hash, secret string, body []byte, sig string) error {
	if sig == "" {
		return ErrMissingSignature
	}
	expected := Sign(h, secret, body)
	if hmac.Equal([]byte(expected), []byte(sig)) {
		return nil
	}
	return ErrInvalidSignature
}
