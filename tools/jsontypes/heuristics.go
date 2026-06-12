package jsontypes

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// looksLikeMap uses heuristics to decide whether an object is a map (keyed
// collection) or a struct. Returns (isMap, confident).
//
// The logic is deliberately asymmetric: a map misidentified as a struct
// explodes into hundreds of fields, while a struct misidentified as a map
// is compact and easy to fix. So when in doubt, default to map.
//
// Three rules:
//  1. All numeric keys → map (certain).
//  2. Any key is a common word → struct (certain).
//  3. Everything else → map (safe default).
func looksLikeMap(obj map[string]any) (isMap bool, confident bool) {
	keys := sortedKeys(obj)
	n := len(keys)
	if n == 0 {
		return false, false
	}

	// Rule 1: All keys are integers → always a map.
	allInts := true
	for _, k := range keys {
		if _, err := strconv.ParseInt(k, 10, 64); err != nil {
			allInts = false
			break
		}
	}
	if allInts {
		return true, true
	}

	// Rule 2: Keys that look like words → struct.
	// With few keys, one word is enough. With many keys, a majority must
	// be words — otherwise a few coincidental matches (e.g., "beef" in hex)
	// could misclassify a map.
	wordCount := countWordLikeKeys(keys)
	if n <= 3 {
		if wordCount >= 1 {
			return false, true
		}
		return true, false
	}
	if wordCount > n/2 {
		return false, true
	}

	// Rule 3: No word majority → default to map.
	return true, true
}

// countWordLikeKeys returns how many keys look like they're composed of words
// (i.e., struct field names rather than IDs/tokens).
func countWordLikeKeys(keys []string) int {
	count := 0
	for _, k := range keys {
		if isWordLikeKey(k) {
			count++
		}
	}
	return count
}

// isWordLikeKey checks whether a key is composed of word-like segments,
// with at least one strong word (3+ chars, pronounceable). Short words
// like "at", "on", "id" only count when paired with a strong word
// (e.g., "created_at" has "created" as the strong word).
//
//	"created_at" → ["created", "at"] → "created" is strong → true
//	"theme"      → ["theme"]        → strong word           → true
//	"at"         → ["at"]           → no strong word         → false
//	"usr_2NBv8C" → ["usr", "2NBv8C"] → "2NBv8C" not a word  → false
func isWordLikeKey(k string) bool {
	segments := splitWordSegments(k)
	if len(segments) == 0 {
		return false
	}
	hasStrongWord := false
	for _, seg := range segments {
		// Pure digits and short segments (< 3 chars) that aren't known
		// short words are neutral — skip without failing.
		// This handles abbreviations like "ms", "db", "ui" in keys
		// like "account_ms" or "build_db".
		if isAllDigits(seg) || (len(seg) < 3 && !commonShortWords[strings.ToLower(seg)]) {
			continue
		}
		if !isWordSegment(seg) {
			return false
		}
		if len(seg) >= 3 && segmentIsPronounceable(seg) {
			hasStrongWord = true
		}
	}
	return hasStrongWord
}

// commonShortWords are words too short for pronounceability checks but
// commonly found in struct field names.
var commonShortWords = map[string]bool{
	"id": true, "at": true, "on": true, "by": true, "in": true,
	"to": true, "of": true, "or": true, "is": true, "no": true,
	"do": true, "up": true, "if": true, "go": true, "ok": true,
}

// isWordSegment returns true if a segment looks like a word.
func isWordSegment(s string) bool {
	if len(s) == 0 {
		return false
	}
	// Pure digits are not words (but are ok as parts of a key like "form1065").
	if isAllDigits(s) {
		return false
	}
	// Short common words.
	if commonShortWords[strings.ToLower(s)] {
		return true
	}
	// 3+ character pronounceable segments are words.
	return len(s) >= 3 && segmentIsPronounceable(s)
}

func segmentIsPronounceable(s string) bool {
	// Strip trailing digits — "form1065" → "form", "line2" → "line".
	core := strings.TrimRightFunc(s, unicode.IsDigit)
	if core == "" {
		return false // all digits
	}
	// If the core still has digits, it's not a word (e.g., "a1b2c3d4" → "a1b2c3d").
	for _, r := range core {
		if unicode.IsDigit(r) {
			return false
		}
	}

	s = strings.ToLower(core)
	vowels := 0
	consonantRun := 0
	maxConsonantRun := 0
	letters := 0

	for _, r := range s {
		if !unicode.IsLetter(r) {
			consonantRun = 0
			continue
		}
		letters++
		if isVowel(r) {
			vowels++
			consonantRun = 0
		} else {
			consonantRun++
			if consonantRun > maxConsonantRun {
				maxConsonantRun = consonantRun
			}
		}
	}

	if letters < 2 {
		return false
	}

	ratio := float64(vowels) / float64(letters)
	// English words typically have 30-50% vowels.
	// Allow a wide band (15-80%) to cover abbreviations and acronyms.
	if ratio < 0.15 || ratio > 0.80 {
		return false
	}
	// No natural word has 5+ consonants in a row.
	if maxConsonantRun > 4 {
		return false
	}
	return true
}

func isVowel(r rune) bool {
	switch r {
	case 'a', 'e', 'i', 'o', 'u', 'y':
		return true
	}
	return false
}

func isAllDigits(s string) bool {
	for _, r := range s {
		if !unicode.IsDigit(r) {
			return false
		}
	}
	return len(s) > 0
}

// splitWordSegments breaks a string into word-like segments by splitting on
// underscores, hyphens, and camelCase boundaries.
func splitWordSegments(s string) []string {
	// First split on underscores and hyphens.
	var parts []string
	for _, part := range strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-'
	}) {
		// Then split on camelCase boundaries.
		parts = append(parts, splitCamelCase(part)...)
	}
	return parts
}

func splitCamelCase(s string) []string {
	var segments []string
	start := 0
	runes := []rune(s)
	for i := 1; i < len(runes); i++ {
		if unicode.IsUpper(runes[i]) && (i > start) {
			segments = append(segments, string(runes[start:i]))
			start = i
		}
	}
	segments = append(segments, string(runes[start:]))
	return segments
}

// inferKeyName tries to infer a meaningful key name from the map's keys.
func inferKeyName(obj map[string]any) string {
	keys := sortedKeys(obj)
	if len(keys) == 0 {
		return "string"
	}

	// All numeric?
	allNum := true
	for _, k := range keys {
		if _, err := strconv.ParseInt(k, 10, 64); err != nil {
			allNum = false
			break
		}
	}
	if allNum {
		return "int"
	}

	// Check if all values are objects with a common field that matches the
	// key (e.g., keys are "abc123" and objects have an "id" field with "abc123").
	// This suggests the key name is "id".
	for _, fieldName := range []string{"id", "ID", "Id", "_id"} {
		match := true
		for k, v := range obj {
			if m, ok := v.(map[string]any); ok {
				if val, exists := m[fieldName]; exists {
					if fmt.Sprintf("%v", val) == k {
						continue
					}
				}
			}
			match = false
			break
		}
		if match && len(obj) > 0 {
			return fieldName
		}
	}

	return "string"
}

// ambiguousTypeNames maps lowercase inferred names to their canonical form.
// When one of these is inferred, the parent type name is prepended and the
// canonical form is used (e.g., "json" in any casing → ParentJSON).
var ambiguousTypeNames = map[string]string{
	"json":   "JSON",
	"data":   "Data",
	"item":   "Item",
	"value":  "Value",
	"result": "Result",
}

// inferTypeName tries to guess a struct name from the path context.
func inferTypeName(path string) string {
	// Root path → "Root"
	if path == "." {
		return "Root"
	}

	// Root-level collection items (no parent type yet)
	// e.g., ".[]", ".[string]", ".[int]"
	if !strings.Contains(path, "{") {
		name := inferTypeNameFromSegments(path)
		if name == "" {
			return "RootItem"
		}
		return name
	}

	return inferTypeNameFromSegments(path)
}

func inferTypeNameFromSegments(path string) string {
	// Extract the last meaningful segment from the path
	// e.g., ".friends[int]" → "Friend", ".{Person}.address" → "Address"
	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '.' || r == '[' || r == ']' || r == '{' || r == '}'
	})
	if len(parts) == 0 {
		return ""
	}
	last := parts[len(parts)-1]
	// Skip index-like segments
	if last == "int" || last == "string" || last == "id" {
		if len(parts) >= 2 {
			last = parts[len(parts)-2]
		} else {
			return ""
		}
	}
	// Strip common suffixes like _id, _key, Id
	last = strings.TrimSuffix(last, "_id")
	last = strings.TrimSuffix(last, "_key")
	last = strings.TrimSuffix(last, "Id")
	last = strings.TrimSuffix(last, "Key")
	if last == "" {
		return ""
	}
	name := singularize(snakeToPascal(last))

	// If the inferred name is too generic, use canonical form and prepend parent
	if canonical, ok := ambiguousTypeNames[strings.ToLower(name)]; ok {
		parent := parentTypeName(path)
		if parent != "" {
			return parent + canonical
		}
		return canonical
	}

	return name
}

// isUbiquitousField returns true if a field name is so common across all
// domains (databases, APIs, languages) that sharing it doesn't imply the
// objects are the same type. These are excluded when deciding whether to
// default to "same" or "different" types.
func isUbiquitousField(name string) bool {
	// Exact matches
	switch name {
	case "id", "ID", "Id", "_id",
		"name", "Name",
		"type", "Type", "_type",
		"kind", "Kind",
		"slug", "Slug",
		"label", "Label",
		"title", "Title",
		"description", "Description":
		return true
	}
	// Suffix patterns: *_at, *_on, *At, *On (timestamps/dates)
	if strings.HasSuffix(name, "_at") || strings.HasSuffix(name, "_on") ||
		strings.HasSuffix(name, "At") || strings.HasSuffix(name, "On") {
		return true
	}
	return false
}

// snakeToPascal converts snake_case or camelCase to PascalCase.
func snakeToPascal(s string) string {
	parts := strings.FieldsFunc(s, func(r rune) bool {
		return r == '_' || r == '-'
	})
	for i, p := range parts {
		parts[i] = capitalize(p)
	}
	return strings.Join(parts, "")
}

func capitalize(s string) string {
	if len(s) == 0 {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

// singularize does a naive singularization for common English plurals.
// shouldMergeObjects decides whether a pool of objects should be treated as
// one struct type with optional fields, rather than multiple distinct types.
//
// Heuristic: if ≥ 2 keys appear in more than half the objects, the objects
// likely share a common shape with optional fields. This catches the common
// case of API responses where every record has the same core fields but some
// records have extra ones (e.g. pagination results).
func shouldMergeObjects(objects []map[string]any) bool {
	n := len(objects)
	if n < 2 {
		return false
	}

	// Count how many objects contain each key.
	keyCount := make(map[string]int)
	for _, obj := range objects {
		for k := range obj {
			keyCount[k]++
		}
	}

	// Count keys that appear in a majority of objects.
	threshold := n / 2
	highFreq := 0
	for _, count := range keyCount {
		if count > threshold {
			highFreq++
		}
	}

	// Two or more high-frequency keys means the objects share a common core.
	return highFreq >= 2
}

func singularize(s string) string {
	// Uncountable / already-singular words ending in -s.
	switch strings.ToLower(s) {
	case "species", "series", "chassis", "status", "alias":
		return s
	}
	if strings.HasSuffix(s, "ies") && len(s) > 4 {
		return s[:len(s)-3] + "y"
	}
	if strings.HasSuffix(s, "ses") || strings.HasSuffix(s, "xes") || strings.HasSuffix(s, "zes") {
		return s[:len(s)-2]
	}
	if strings.HasSuffix(s, "ss") || strings.HasSuffix(s, "us") || strings.HasSuffix(s, "is") {
		return s // not plural
	}
	if strings.HasSuffix(s, "s") && len(s) > 3 {
		return s[:len(s)-1]
	}
	return s
}
