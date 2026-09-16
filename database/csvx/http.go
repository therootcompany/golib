// Copyright 2025 Cogburn Bros
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain a copy at https://mozilla.org/MPL/2.0/.

package csvx

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
)

// Format is a canonical output format.
type Format string

const (
	// DefaultFormat is csv — project rule: all new routes default to CSV.
	DefaultFormat Format = "csv"
	FormatCSV     Format = "csv"
	FormatTSV     Format = "tab"
	FormatJSON    Format = "json"
	FormatJSONL   Format = "jsonl"
)

// ContentType maps canonical format to MIME type.
func ContentType(f Format) string {
	switch f {
	case FormatCSV:
		return "text/csv"
	case FormatTSV:
		return "text/tab-separated-values"
	case FormatJSONL:
		return "application/x-ndjson"
	default:
		return "application/json"
	}
}

// normalize maps ?format= values to canonical format names.
func normalize(s string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "csv":
		return FormatCSV, true
	case "tsv", "tab":
		return FormatTSV, true
	case "json":
		return FormatJSON, true
	case "ndjson", "jsonl":
		return FormatJSONL, true
	}
	return "", false
}

// mediaFormat maps Accept media types to canonical format names.
func mediaFormat(media string) (Format, bool) {
	switch strings.ToLower(strings.TrimSpace(media)) {
	case "text/csv":
		return FormatCSV, true
	case "text/tab-separated-values":
		return FormatTSV, true
	case "application/json", "text/json":
		return FormatJSON, true
	case "application/x-ndjson", "application/jsonl":
		return FormatJSONL, true
	}
	return "", false
}

// ResolveFormat returns the output format for a request. ?format= has
// priority. Otherwise the Accept header's best q-matched media type is used.
// Per project rule, the default (empty Accept, */*, or no match) is CSV.
// Returns an error only for an explicit unknown ?format= value.
func ResolveFormat(r *http.Request) (Format, error) {
	if f := r.URL.Query().Get("format"); f != "" {
		format, ok := normalize(f)
		if !ok {
			return "", fmt.Errorf("unsupported format %q (accepted: csv, tsv, json, jsonl)", f)
		}
		return format, nil
	}
	return acceptFormat(r.Header.Get("Accept"))
}

// acceptFormat inspects the Accept header's quality values and returns the
// best-matching format. Defaults to CSV when the header is empty, wildcarded,
// or has no matching media type.
func acceptFormat(accept string) (Format, error) {
	best, bestQ := DefaultFormat, -1.0
	found := false

	for part := range strings.SplitSeq(accept, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		media := part
		q := 1.0
		if before, after, ok := strings.Cut(part, ";"); ok {
			media = before
			for param := range strings.SplitSeq(after, ";") {
				param = strings.TrimSpace(param)
				if strings.HasPrefix(strings.ToLower(param), "q=") {
					if parsed, err := strconv.ParseFloat(strings.TrimSpace(param[2:]), 64); err == nil {
						q = parsed
					}
				}
			}
		}
		media = strings.TrimSpace(media)

		var f Format
		var ok bool
		if media == "*/*" {
			f, ok = DefaultFormat, true
		} else {
			f, ok = mediaFormat(media)
		}
		if ok && q > bestQ {
			best, bestQ, found = f, q, true
		}
	}

	if !found {
		return DefaultFormat, nil
	}
	return best, nil
}
