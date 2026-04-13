// Authored in 2026 by AJ ONeal <aj@therootcompany.com>, assisted by AI.
// To the extent possible under law, the author(s) have dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// You should have received a copy of the CC0 Public Domain Dedication along with
// this software. If not, see <https://creativecommons.org/publicdomain/zero/1.0/>.
//
// SPDX-License-Identifier: CC0-1.0

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
