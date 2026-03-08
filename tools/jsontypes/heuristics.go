package jsontypes

import (
	"encoding/base64"
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
	if n < 3 {
		// Too few keys to be confident about anything
		return false, false
	}

	// All keys are integers?
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

	// All keys same length and contain mixed letters+digits → likely IDs
	if allSameLength(keys) && allAlphanumericWithDigits(keys) {
		return true, true
	}

	// All keys same length and look like base64/hex IDs
	if allSameLength(keys) && allLookLikeIDs(keys) {
		return true, true
	}

	// Keys look like typical struct field names (camelCase, snake_case, short words)
	// This must be checked before value-shape heuristics: a struct with many
	// fields whose values happen to share a shape is still a struct.
	if allLookLikeFieldNames(keys) {
		return false, true
	}

	// Large number of keys where most values have the same shape — likely a map
	if n > 20 && valuesHaveSimilarShape(obj) {
		return true, true
	}

	return false, false
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
// names: no spaces, alphanumeric/base64/hex, and not common English field names.
func allLookLikeIDs(keys []string) bool {
	for _, k := range keys {
		if strings.ContainsAny(k, " \t\n") {
			return false
		}
		// Hex or base64 strings of any length ≥ 4
		if len(k) >= 4 && (isHex(k) || isAlphanumeric(k) || isBase64(k)) {
			continue
		}
		return false
	}
	// Additional check: IDs typically don't look like field names.
	// If ALL of them look like field names (e.g., camelCase), not IDs.
	if allLookLikeFieldNames(keys) {
		return false
	}
	return true
}

func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
	}
	return true
}

// allAlphanumericWithDigits checks if all keys are alphanumeric and each
// contains at least one digit (distinguishing IDs like "abc123" from field
// names like "name").
func allAlphanumericWithDigits(keys []string) bool {
	for _, k := range keys {
		hasDigit := false
		for _, r := range k {
			if unicode.IsDigit(r) {
				hasDigit = true
			} else if !unicode.IsLetter(r) {
				return false
			}
		}
		if !hasDigit {
			return false
		}
	}
	return true
}

func isBase64(s string) bool {
	// Try standard and URL-safe base64
	if _, err := base64.StdEncoding.DecodeString(s); err == nil {
		return true
	}
	if _, err := base64.URLEncoding.DecodeString(s); err == nil {
		return true
	}
	if _, err := base64.RawURLEncoding.DecodeString(s); err == nil {
		return true
	}
	return false
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
