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
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"errors"
	"fmt"
	"hash"
	"io"
	"net/http"
	"strings"
)

const DefaultLimit = 256 * 1024

type Hash struct {
	Header string
	New    func() hash.Hash
	Prefix string
}

var SHA256 = Hash{
	Header: "X-Hub-Signature-256",
	New:    sha256.New,
	Prefix: "sha256=",
}

var SHA1 = Hash{
	Header: "X-Hub-Signature",
	New:    sha1.New,
	Prefix: "sha1=",
}

type XHubSig struct {
	Secret    string
	Hashes    []Hash
	AcceptAny bool
	Limit     int64
}

func New(secret string, hashes ...Hash) *XHubSig {
	if len(hashes) == 0 {
		hashes = []Hash{SHA256}
	}
	return &XHubSig{
		Secret:    secret,
		Hashes:    hashes,
		AcceptAny: false,
		Limit:     DefaultLimit,
	}
}

// signatureHint builds a pseudocode hint showing how to compute each
// configured signature header using the webhook secret.
func (x *XHubSig) signatureHint() string {
	lines := make([]string, len(x.Hashes))
	for i, h := range x.Hashes {
		algo := strings.TrimSuffix(h.Prefix, "=")
		lines[i] = fmt.Sprintf("`%s: %shex(hmac_%s(secret, body))`", h.Header, h.Prefix, algo)
	}
	return strings.Join(lines, "\n")
}

func (x *XHubSig) writeHTTPError(w http.ResponseWriter, r *http.Request, errCode, detail string) {
	var (
		httpCode    int
		description string
		hint        string
	)
	switch errCode {
	case "body_too_large":
		httpCode = http.StatusRequestEntityTooLarge
		description = "Request body exceeds the maximum allowed size."
		hint = detail + "; reduce the payload size."
	case "missing_signature":
		httpCode = http.StatusUnauthorized
		description = "No valid signature header was found."
		hint = detail + "\n" + x.signatureHint()
	case "invalid_signature":
		httpCode = http.StatusUnauthorized
		description = "Signature verification failed."
		hint = detail + "\n" + x.signatureHint()
	default:
		httpCode = http.StatusInternalServerError
		description = "An unexpected error occurred."
	}
	serializeError(w, r, httpCode, httpError{
		Error:       errCode,
		Description: description,
		Hint:        hint,
	})
}

func (x *XHubSig) readBody(r *http.Request) ([]byte, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, x.Limit+1))
	r.Body.Close()
	if len(body) > int(x.Limit) {
		return nil, ErrBodyTooLarge
	}
	if err != nil {
		return nil, err
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

func (x *XHubSig) Require(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := x.readBody(r)
		if err != nil {
			if errors.Is(err, ErrBodyTooLarge) {
				x.writeHTTPError(w, r, "body_too_large", fmt.Sprintf("limit is %d bytes", x.Limit))
				return
			}
			w.WriteHeader(http.StatusBadRequest) // for loggers; client cannot receive a body
			return
		}

		anyPresent := false
		for _, h := range x.Hashes {
			sig := r.Header.Get(h.Header)
			if sig == "" {
				if !x.AcceptAny {
					x.writeHTTPError(w, r, "missing_signature", fmt.Sprintf("%s is required", h.Header))
					return
				}
				continue
			}
			anyPresent = true
			if err := Verify(h, x.Secret, body, sig); err != nil {
				x.writeHTTPError(w, r, "invalid_signature", fmt.Sprintf("%s value did not match the expected HMAC", h.Header))
				return
			}
		}
		if !anyPresent {
			headers := make([]string, len(x.Hashes))
			for i, h := range x.Hashes {
				headers[i] = h.Header
			}
			x.writeHTTPError(w, r, "missing_signature", "expected one of: "+strings.Join(headers, ", "))
			return
		}

		next.ServeHTTP(w, r)
	})
}
