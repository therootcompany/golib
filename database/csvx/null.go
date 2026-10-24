package csvx

import "strings"

// isBoolNull reports whether a human-edited cell means "not supplied":
// empty/whitespace-only, the exact PG dump sentinel `\N` (case-sensitive),
// or a case-insensitive match of null, \null, none, or unknown.
//
// Bool and BoolishTimestamp read such cells as absent. Free-text types
// must not reuse this set wholesale: most of these words are legitimate
// text values in non-boolean contexts.
func isBoolNull(raw string) bool {
	s := strings.TrimSpace(raw)
	if s == "" || s == `\N` {
		return true
	}
	switch strings.ToLower(s) {
	case "null", `\null`, "none", "unknown":
		return true
	}
	return false
}
