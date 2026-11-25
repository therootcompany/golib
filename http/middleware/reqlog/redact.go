// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) has dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// SPDX-License-Identifier: CC0-1.0

package reqlog

import (
	"net/url"
	"strings"
)

// redact.go is the logging policy expressed as data, not a fork of the
// logger. Redaction masks secrets in the log record; it never touches the
// live request.

// keepLast is how many trailing characters MaskKeepLast preserves.
const keepLast = 4

// MaskMode decides how a secret value appears in the log record.
type MaskMode int

const (
	// MaskKeepLast keeps the last four characters of the value and replaces
	// the rest with '*', so a support agent can correlate a ticket with a
	// log line without the log containing the secret.
	MaskKeepLast MaskMode = iota

	// MaskDelete removes the value entirely.
	MaskDelete
)

// Redaction is the per-service logging policy.
type Redaction struct {
	// QueryDeny lists query parameter names whose values are masked before
	// logging (access_token, id_token, code, sig, …).
	QueryDeny []string

	// PathSecrets lists paths whose secret segment is masked. A segment is a
	// literal that must match, or a wildcard - "*" or "{name}" - that matches
	// exactly one path segment, e.g. "/rooms/*" or "/auth/{email}".
	PathSecrets []string

	// Mask is the masking mode; MaskKeepLast is the default.
	Mask MaskMode
}

// sanitizeQuery masks the values of deny-listed parameters. Everything else
// keeps its position and encoding, so the query still reads like the request.
func sanitizeQuery(rawQuery string, red Redaction) string {
	if rawQuery == "" || len(red.QueryDeny) == 0 {
		return rawQuery
	}

	deny := make(map[string]struct{}, len(red.QueryDeny))
	for _, name := range red.QueryDeny {
		deny[name] = struct{}{}
	}

	pairs := strings.Split(rawQuery, "&")
	for i, pair := range pairs {
		name, value, hasValue := strings.Cut(pair, "=")
		if !hasValue {
			continue
		}
		key, err := url.QueryUnescape(name)
		if err != nil {
			key = name
		}
		if _, ok := deny[key]; !ok {
			continue
		}
		pairs[i] = name + "=" + mask(value, red.Mask)
	}
	return strings.Join(pairs, "&")
}

// sanitizePath masks the segments matched by PathSecrets.
func sanitizePath(path string, red Redaction) string {
	if path == "" || len(red.PathSecrets) == 0 {
		return path
	}

	segments := strings.Split(path, "/")
	for _, pattern := range red.PathSecrets {
		segs := strings.Split(strings.Trim(pattern, "/"), "/")
		if len(segs) == 0 {
			continue
		}
		for start := 0; start+len(segs) <= len(segments); start++ {
			if !matchSegments(segments, start, segs) {
				continue
			}
			for j, seg := range segs {
				if isWildcard(seg) {
					segments[start+j] = mask(segments[start+j], red.Mask)
				}
			}
		}
	}
	return strings.Join(segments, "/")
}

// matchSegments reports whether pattern aligns with segments at start.
func matchSegments(segments []string, start int, pattern []string) bool {
	for j, want := range pattern {
		got := segments[start+j]
		if isWildcard(want) {
			if got == "" {
				return false
			}
			continue
		}
		if got != want {
			return false
		}
	}
	return true
}

// isWildcard reports whether a pattern segment matches any single path
// segment: "*" or "{name}".
func isWildcard(seg string) bool {
	return seg == "*" || (len(seg) > 2 && seg[0] == '{' && seg[len(seg)-1] == '}')
}

// mask applies the redaction mode to a single value. MaskKeepLast keeps the
// last four characters; a value that short is masked entirely, since four
// characters of a four-character secret is the secret.
func mask(value string, mode MaskMode) string {
	if mode == MaskDelete {
		return ""
	}
	runes := []rune(value)
	if len(runes) <= keepLast {
		return strings.Repeat("*", len(runes))
	}
	return strings.Repeat("*", len(runes)-keepLast) + string(runes[len(runes)-keepLast:])
}
