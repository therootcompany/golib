// Package csvx provides text normalization and format detection helpers.
package csvx

import (
	"path/filepath"
	"regexp"
	"strings"
)

var phoneStripRe = regexp.MustCompile(`[^\d,#*]`)

// NormalizePhone strips non-digit characters and formats 10-digit US numbers
// to (xxx) xxx-xxxx. Non-US or non-standard numbers are returned digit-only.
func NormalizePhone(raw string) string {
	stripped := phoneStripRe.ReplaceAllString(raw, "")
	if len(stripped) == 11 && stripped[0] == '1' {
		stripped = stripped[1:]
	}
	if len(stripped) == 10 {
		return "(" + stripped[0:3] + ") " + stripped[3:6] + "-" + stripped[6:10]
	}
	return stripped
}

// NormalizeEmail trims whitespace and lowercases.
func NormalizeEmail(raw string) string {
	return strings.ToLower(strings.TrimSpace(raw))
}

// DetectFormat returns the format from a file extension.
func DetectFormat(filename string) string {
	switch ext := strings.ToLower(filepath.Ext(filename)); ext {
	case ".tsv", ".tab":
		return "tsv"
	case ".csv":
		return "csv"
	case ".json":
		return "json"
	case ".jsonl", ".ndjson":
		return "jsonl"
	default:
		return "csv"
	}
}
