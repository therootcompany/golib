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
// logger. Redaction masks secret values in the log record; it never touches
// the live request.

// keepLast is the default number of trailing characters a mask preserves.
const keepLast = 4

// MaskMode is the fallback for a masked value that has no Keep rule.
type MaskMode int

const (
	// MaskKeepLast keeps the last four characters of the value and replaces
	// the rest with '*', so a support agent can correlate a ticket with a
	// log line without the log containing the secret.
	MaskKeepLast MaskMode = iota

	// MaskDelete removes the value entirely.
	MaskDelete
)

// RedactionMode picks which side of the fence is logged in full.
type RedactionMode int

const (
	// RedactBlacklist - the deny list, and the default - logs every value
	// except the names in QueryDeny. Forgiving: nothing is hidden unless you
	// name it.
	RedactBlacklist RedactionMode = iota

	// RedactWhitelist - the allow list - logs only the names in QueryAllow
	// and masks everything else. Paranoid by default, so a parameter added
	// next month is masked rather than leaked. A name in QueryDeny is masked
	// even when it is also in QueryAllow, and its Keep rule decides how much
	// of the value survives.
	RedactWhitelist
)

// Keep is how much of a value survives the mask: Prefix leading characters,
// Suffix trailing characters. Which end to keep is a data question, not a
// style one: a ULID is ordered by time, so its prefix is the useful half; an
// opaque token is random, so its tail is the half that identifies the event.
//
// Keeping nothing deletes the value. A rule that covers the whole value masks
// the whole value - a mask that keeps everything hides nothing.
type Keep struct {
	Prefix int
	Suffix int
}

// Redaction is the per-service logging policy.
type Redaction struct {
	// Mode is the polarity of the lists; RedactBlacklist is the default.
	Mode RedactionMode

	// QueryAllow lists query parameter names logged in full in whitelist
	// mode. Ignored in blacklist mode.
	QueryAllow []string

	// QueryDeny lists query parameter names whose values are masked
	// (access_token, id_token, code, sig, …). In whitelist mode it is the
	// override: a name in both lists is masked.
	QueryDeny []string

	// PathSecrets lists paths whose secret segment is masked. A segment is a
	// literal that must match, or a wildcard - "*" or "{name}" - that matches
	// exactly one path segment, e.g. "/rooms/*" or "/auth/{email}".
	// Patterns are masked in both modes.
	PathSecrets []string

	// Keep overrides the mask for a query parameter (by name) or a path
	// pattern (written as given, e.g. "/rooms/*"). Values not named here use
	// Mask.
	Keep map[string]Keep

	// Mask is the fallback for masked values with no Keep rule;
	// MaskKeepLast is the default.
	Mask MaskMode
}

// sanitizeQuery masks the values of every parameter the policy redacts,
// preserving the order and encoding of the rest, so the query still reads
// like the request.
func sanitizeQuery(rawQuery string, red Redaction) string {
	if rawQuery == "" || !red.hasQueryPolicy() {
		return rawQuery
	}

	allow := nameSet(red.QueryAllow)
	deny := nameSet(red.QueryDeny)

	pairs := strings.Split(rawQuery, "&")
	for i, pair := range pairs {
		name, value, hasValue := strings.Cut(pair, "=")
		if !hasValue || value == "" {
			continue
		}
		key, err := url.QueryUnescape(name)
		if err != nil {
			key = name
		}
		if !redactsQuery(key, allow, deny, red.Mode) {
			continue
		}
		pairs[i] = name + "=" + mask(value, red.keepFor(key))
	}
	return strings.Join(pairs, "&")
}

// redactsQuery reports whether a parameter's value is masked under the mode.
func redactsQuery(name string, allow, deny map[string]struct{}, mode RedactionMode) bool {
	if _, ok := deny[name]; ok {
		return true
	}
	if mode == RedactWhitelist {
		_, ok := allow[name]
		return !ok
	}
	return false
}

// hasQueryPolicy reports whether the query needs touching at all.
func (r Redaction) hasQueryPolicy() bool {
	return r.Mode == RedactWhitelist || len(r.QueryDeny) > 0 || len(r.QueryAllow) > 0
}

// keepFor returns the keep rule for a parameter name or a path pattern,
// falling back to the Mask mode.
func (r Redaction) keepFor(name string) Keep {
	if keep, ok := r.Keep[name]; ok {
		return keep
	}
	if r.Mask == MaskDelete {
		return Keep{}
	}
	return Keep{Suffix: keepLast}
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
		keep := red.keepFor(pattern)
		for start := 0; start+len(segs) <= len(segments); start++ {
			if !matchSegments(segments, start, segs) {
				continue
			}
			for j, seg := range segs {
				if isWildcard(seg) {
					segments[start+j] = mask(segments[start+j], keep)
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

// mask keeps the characters named by the keep rule and replaces the rest with
// '*'. Keeping nothing deletes the value; a rule that covers the whole value
// masks the whole value, because a mask that keeps everything hides nothing.
func mask(value string, keep Keep) string {
	runes := []rune(value)
	n := len(runes)

	prefix := clamp(keep.Prefix, 0, n)
	suffix := clamp(keep.Suffix, 0, n)
	if prefix+suffix == 0 {
		return ""
	}
	if prefix+suffix >= n {
		return strings.Repeat("*", n)
	}
	return string(runes[:prefix]) + strings.Repeat("*", n-prefix-suffix) + string(runes[n-suffix:])
}

func clamp(n, min, max int) int {
	if n < min {
		return min
	}
	if n > max {
		return max
	}
	return n
}

// nameSet turns a list of names into a lookup set.
func nameSet(names []string) map[string]struct{} {
	set := make(map[string]struct{}, len(names))
	for _, name := range names {
		set[name] = struct{}{}
	}
	return set
}
