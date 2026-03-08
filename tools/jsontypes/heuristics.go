package jsontypes

import (
	"fmt"
	"strconv"
	"strings"
	"unicode"
)

// looksLikeMap uses heuristics to guess whether an object is a map (keyed
// collection) rather than a struct. Returns true/false and a confidence hint.
// If confidence is low, the caller should prompt the user.
func looksLikeMap(obj map[string]any) (isMap bool, confident bool) {
	keys := sortedKeys(obj)
	n := len(keys)

	// All keys are integers → always a map, even with 1 key.
	allInts := true
	for _, k := range keys {
		if _, err := strconv.ParseInt(k, 10, 64); err != nil {
			allInts = false
			break
		}
	}
	if allInts && n > 0 {
		return true, true
	}

	// If any key is a well-known struct field name, it's definitely a struct.
	// This catches 1-2 key objects like {"name": ..., "age": ...}.
	if hasKnownFieldName(keys) {
		return false, true
	}

	// All keys contain mixed letters+digits → likely IDs (e.g., "emp_101").
	if allContainDigits(keys) {
		return true, true
	}

	// All keys same length and look like base64/hex IDs.
	if allSameLength(keys) && allLookLikeIDs(keys) {
		return true, true
	}

	if n < 3 {
		// Too few keys and no strong signal either way.
		return false, false
	}

	// Keys look like typical struct field names (camelCase, snake_case, short words).
	// This must be checked before value-shape heuristics: a struct with many
	// fields whose values happen to share a shape is still a struct.
	if allLookLikeFieldNames(keys) {
		return false, true
	}

	// Large number of keys where most values have the same shape → likely a map.
	if n > 20 && valuesHaveSimilarShape(obj) {
		return true, true
	}

	return false, false
}

// hasKnownFieldName returns true if any key matches a well-known struct field
// name. A single match is a strong signal — real maps don't have keys named
// "created_at" or "email".
func hasKnownFieldName(keys []string) bool {
	for _, k := range keys {
		if isKnownFieldName(k) {
			return true
		}
	}
	return false
}

// isKnownFieldName checks whether a key is a common struct/object field name.
// This is deliberately broad — false positives (calling a map key a field)
// are less harmful than false negatives (treating a struct as a map).
func isKnownFieldName(k string) bool {
	lower := strings.ToLower(k)

	// Suffix patterns: timestamps, flags, relations
	suffixes := []string{
		"_at", "_on", "_by", "_id", "_ids", "_url", "_uri",
		"_name", "_type", "_kind", "_key", "_code", "_date",
		"_count", "_size", "_path", "_hash", "_token",
		"_enabled", "_disabled", "_active", "_status",
	}
	for _, s := range suffixes {
		if strings.HasSuffix(lower, s) {
			return true
		}
	}
	// camelCase suffixes
	camelSuffixes := []string{
		"At", "On", "By", "Id", "Ids", "Url", "Uri",
		"Name", "Type", "Kind", "Key", "Code", "Date",
		"Count", "Size", "Path", "Hash", "Token",
	}
	for _, s := range camelSuffixes {
		if strings.HasSuffix(k, s) && len(k) > len(s) {
			return true
		}
	}

	// Exact matches: common field names across APIs
	switch lower {
	case
		// identity
		"id", "uid", "uuid", "guid", "slug",
		// naming
		"name", "title", "label", "description", "summary",
		// typing/classification
		"type", "kind", "category", "class", "role", "status", "state",
		// content
		"value", "data", "content", "body", "text", "message", "comment",
		"url", "uri", "href", "link", "path",
		"email", "phone", "address",
		// flags
		"active", "enabled", "disabled", "visible", "hidden",
		"required", "optional", "readonly", "deleted", "archived",
		"public", "private", "verified", "approved", "published",
		// numbers
		"count", "total", "size", "length", "width", "height",
		"amount", "price", "cost", "quantity", "weight",
		"score", "rating", "level", "priority", "order", "index", "position",
		"version", "revision",
		"min", "max", "limit", "offset", "page",
		"latitude", "longitude", "lat", "lng", "lon",
		// structure
		"parent", "children", "items", "entries", "results", "records",
		"tags", "labels", "groups", "members", "users", "roles",
		"permissions", "scopes", "features", "options", "settings",
		"config", "configuration", "preferences", "metadata", "meta",
		"errors", "warnings",
		// media
		"format", "encoding", "charset", "locale", "language", "currency",
		"color", "icon", "image", "avatar", "thumbnail", "logo",
		"filename", "extension", "mimetype",
		// auth
		"username", "password", "token", "secret", "credential",
		// time
		"date", "time", "timestamp", "duration", "interval",
		"start", "end", "expires":
		return true
	}

	// Prefix patterns: is_*, has_*, can_*, should_*, allow_*
	prefixes := []string{"is_", "has_", "can_", "should_", "allow_", "num_"}
	for _, p := range prefixes {
		if strings.HasPrefix(lower, p) {
			return true
		}
	}

	return false
}

// allContainDigits checks if every key contains at least one digit,
// suggesting they are IDs rather than field names (e.g., "emp_101", "abc123").
func allContainDigits(keys []string) bool {
	if len(keys) == 0 {
		return false
	}
	for _, k := range keys {
		hasDigit := false
		for _, r := range k {
			if unicode.IsDigit(r) {
				hasDigit = true
				break
			}
		}
		if !hasDigit {
			return false
		}
	}
	return true
}

func allSameLength(keys []string) bool {
	if len(keys) == 0 {
		return true
	}
	l := len(keys[0])
	for _, k := range keys[1:] {
		if len(k) != l {
			return false
		}
	}
	return true
}

// allLookLikeIDs checks if keys look like identifiers/tokens rather than field
// names. Uses hex detection, pronounceability, and field name checks.
func allLookLikeIDs(keys []string) bool {
	for _, k := range keys {
		if strings.ContainsAny(k, " \t\n") {
			return false
		}
		// Pure hex is always an ID.
		if len(k) >= 4 && isHex(k) {
			continue
		}
		// Pronounceable strings are field names, not IDs.
		if isPronounceable(k) {
			return false
		}
		// Non-pronounceable alphanumeric of sufficient length → likely ID.
		if len(k) >= 4 && isAlphanumeric(k) {
			continue
		}
		// Doesn't match any ID pattern.
		return false
	}
	return len(keys) > 0
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}



// isPronounceable checks whether a string has the vowel/consonant rhythm of
// natural language. Field names like "metadata", "created_at", "userName" are
// pronounceable; tokens like "a1b2c3d4", "dGVzdA==", "xK9mP4q" are not.
//
// The check splits on underscores and case boundaries (camelCase), then
// verifies each word-like segment has a reasonable vowel ratio (15-80%) and
// no long consonant runs (>4). Pure-digit segments are ignored.
func isPronounceable(s string) bool {
	// Split on underscores, then on camelCase boundaries.
	segments := splitWordSegments(s)
	if len(segments) == 0 {
		return false
	}

	pronounceable := 0
	total := 0
	for _, seg := range segments {
		// Skip pure digits and very short segments.
		if len(seg) < 2 || isAllDigits(seg) {
			continue
		}
		total++
		if segmentIsPronounceable(seg) {
			pronounceable++
		}
	}

	if total == 0 {
		return false
	}
	// Most segments should be pronounceable.
	return pronounceable > total/2
}

func segmentIsPronounceable(s string) bool {
	s = strings.ToLower(s)
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

func isHex(s string) bool {
	for _, r := range s {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

// allLookLikeFieldNames checks if keys look like typical struct field names:
// camelCase, snake_case, PascalCase, or short lowercase words.
func allLookLikeFieldNames(keys []string) bool {
	fieldLike := 0
	for _, k := range keys {
		if looksLikeFieldName(k) {
			fieldLike++
		}
	}
	// If >80% look like field names, probably a struct
	return fieldLike > len(keys)*4/5
}

func looksLikeFieldName(k string) bool {
	if len(k) == 0 || len(k) > 40 {
		return false
	}
	// Must start with a letter
	runes := []rune(k)
	if !unicode.IsLetter(runes[0]) {
		return false
	}
	// Only letters, digits, underscores
	for _, r := range runes {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) && r != '_' {
			return false
		}
	}
	return true
}

// valuesHaveSimilarShape checks if most values in the object are objects with
// similar key sets.
func valuesHaveSimilarShape(obj map[string]any) bool {
	shapes := make(map[string]int)
	total := 0
	for _, v := range obj {
		if m, ok := v.(map[string]any); ok {
			shapes[shapeSignature(m)]++
			total++
		}
	}
	if total == 0 {
		return false
	}
	// Find most common shape
	maxCount := 0
	for _, count := range shapes {
		if count > maxCount {
			maxCount = count
		}
	}
	return maxCount > total/2
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
	parts := strings.Split(s, "_")
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
func singularize(s string) string {
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
