package jsontypes

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Coalesce takes streamer output lines and returns coalesced lines with:
//   - Types deduplicated by key set (same keys = same type)
//   - Nullable annotation ({string?} when {null} + concrete type at same path)
//   - Cleaner type names (no number when unique, per-base-name numbering for conflicts)
//   - Duplicate type definitions elided (referenced by name only)
func Coalesce(lines []string) []string {
	parsed := parseRawLines(lines)
	types := buildCoalesceTypes(parsed)
	groups := groupTypesByKeySet(types)
	nameMap := assignCanonicalNames(groups)
	nullables := detectNullablePaths(parsed)
	return emitCoalesced(parsed, nameMap, nullables)
}

// rawLine is a parsed streamer output line.
type rawLine struct {
	path    string // everything before the last {
	typeVal string // everything inside the last {}
}

func parseRawLines(lines []string) []rawLine {
	result := make([]rawLine, 0, len(lines))
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		result = append(result, parseRawLine(line))
	}
	return result
}

func parseRawLine(line string) rawLine {
	idx := strings.LastIndex(line, "{")
	if idx < 0 || !strings.HasSuffix(line, "}") {
		return rawLine{path: line}
	}
	return rawLine{
		path:    line[:idx],
		typeVal: line[idx+1 : len(line)-1],
	}
}

var namedTypePattern = regexp.MustCompile(`^[A-Z][a-zA-Z0-9-]*\d+$`)

func isNamedType(typeVal string) bool {
	return namedTypePattern.MatchString(typeVal)
}

// coalesceType is a named type from the streamer output.
type coalesceType struct {
	name    string   // original name, e.g., "Ability2"
	path    string   // path where introduced
	keys    []string // sorted direct field names
	keysSig string   // comma-joined keys for comparison
}

func buildCoalesceTypes(lines []rawLine) []*coalesceType {
	var types []*coalesceType

	for i, line := range lines {
		if !isNamedType(line.typeVal) {
			continue
		}

		// Find the extent: until next type intro at the same path.
		end := len(lines)
		for j := i + 1; j < len(lines); j++ {
			if isNamedType(lines[j].typeVal) && lines[j].path == line.path {
				end = j
				break
			}
		}

		// Extract direct field names from lines[i+1:end].
		prefix := coalesceFieldPrefix(line.path)
		fieldNames := make(map[string]bool)
		for j := i + 1; j < end; j++ {
			p := lines[j].path
			if !strings.HasPrefix(p, prefix) {
				continue
			}
			remainder := p[len(prefix):]
			// Direct field: no "." in the remainder.
			if strings.Contains(remainder, ".") {
				continue
			}
			// Strip array brackets to get field name.
			bracketIdx := strings.Index(remainder, "[")
			var fieldName string
			if bracketIdx < 0 {
				fieldName = remainder
			} else {
				fieldName = remainder[:bracketIdx]
			}
			if fieldName != "" {
				fieldNames[fieldName] = true
			}
		}

		keys := make([]string, 0, len(fieldNames))
		for k := range fieldNames {
			keys = append(keys, k)
		}
		sort.Strings(keys)

		types = append(types, &coalesceType{
			name:    line.typeVal,
			path:    line.path,
			keys:    keys,
			keysSig: strings.Join(keys, ","),
		})
	}

	return types
}

// keySetGroup holds all types that share the same key set.
type keySetGroup struct {
	keysSig string
	keys    []string
	members []*coalesceType
}

func groupTypesByKeySet(types []*coalesceType) []*keySetGroup {
	groupMap := make(map[string]*keySetGroup)
	var groups []*keySetGroup

	for _, t := range types {
		if g, ok := groupMap[t.keysSig]; ok {
			g.members = append(g.members, t)
		} else {
			g = &keySetGroup{
				keysSig: t.keysSig,
				keys:    t.keys,
				members: []*coalesceType{t},
			}
			groupMap[t.keysSig] = g
			groups = append(groups, g)
		}
	}

	return groups
}

func assignCanonicalNames(groups []*keySetGroup) map[string]string {
	nameMap := make(map[string]string) // old name → new name

	// Pick a base name for each group.
	type groupName struct {
		group    *keySetGroup
		baseName string
	}
	var gns []groupName
	baseNameCount := make(map[string]int)
	for _, g := range groups {
		name := pickGroupName(g)
		gns = append(gns, groupName{g, name})
		baseNameCount[name]++
	}

	// Assign final names, numbering when base names conflict.
	baseNameCounter := make(map[string]int)
	for _, gn := range gns {
		var finalName string
		if baseNameCount[gn.baseName] == 1 {
			finalName = gn.baseName
		} else {
			idx := baseNameCounter[gn.baseName]
			baseNameCounter[gn.baseName]++
			finalName = fmt.Sprintf("%s%d", gn.baseName, idx)
		}
		for _, t := range gn.group.members {
			nameMap[t.name] = finalName
		}
	}

	return nameMap
}

// pickGroupName selects the best canonical name for a key-set group.
func pickGroupName(g *keySetGroup) string {
	// Count distinct base names among members.
	baseNames := make(map[string]int)
	var firstBase string
	for _, t := range g.members {
		base := stripTrailingDigits(t.name)
		baseNames[base]++
		if firstBase == "" {
			firstBase = base
		}
	}

	// If many distinct names share this shape, derive from keys
	// (e.g., {name, url} → "NameUrl").
	if len(baseNames) > 2 {
		return deriveNameFromKeys(g.keys)
	}

	// If one base name dominates, use it.
	if len(baseNames) == 1 {
		return firstBase
	}

	// Two distinct names — pick the most common, then shortest.
	var best string
	var bestCount int
	for name, count := range baseNames {
		if count > bestCount {
			best = name
			bestCount = count
		} else if count == bestCount && len(name) < len(best) {
			best = name
		}
	}
	return best
}

func deriveNameFromKeys(keys []string) string {
	if len(keys) == 0 {
		return "Unknown"
	}
	// Use all keys (up to 3) to form the name.
	n := len(keys)
	if n > 3 {
		n = 3
	}
	var parts []string
	for _, k := range keys[:n] {
		parts = append(parts, snakeToPascal(k))
	}
	return strings.Join(parts, "")
}

// stripTrailingDigits removes trailing digits from a type name.
func stripTrailingDigits(name string) string {
	i := len(name) - 1
	for i >= 0 && name[i] >= '0' && name[i] <= '9' {
		i--
	}
	if i < 0 {
		return name
	}
	return name[:i+1]
}

// detectNullablePaths returns the set of paths where {null} appears
// alongside at least one concrete type.
func detectNullablePaths(lines []rawLine) map[string]bool {
	pathTypes := make(map[string][]string)
	for _, line := range lines {
		pathTypes[line.path] = append(pathTypes[line.path], line.typeVal)
	}

	nullables := make(map[string]bool)
	for path, typeVals := range pathTypes {
		hasNull := false
		hasOther := false
		for _, tv := range typeVals {
			if tv == "null" {
				hasNull = true
			} else if tv != "undefined" && tv != "empty" {
				hasOther = true
			}
		}
		if hasNull && hasOther {
			nullables[path] = true
		}
	}

	return nullables
}

func emitCoalesced(lines []rawLine, nameMap map[string]string, nullables map[string]bool) []string {
	emittedTypes := make(map[string]bool) // canonical name → already expanded
	var result []string

	i := 0
	for i < len(lines) {
		line := lines[i]

		// Skip standalone {null} lines at nullable paths (merged into ?).
		if line.typeVal == "null" && nullables[line.path] {
			i++
			continue
		}

		if isNamedType(line.typeVal) {
			canonicalName := nameMap[line.typeVal]
			nullable := ""
			if nullables[line.path] {
				nullable = "?"
			}

			if emittedTypes[canonicalName] {
				// Emit reference only, skip field lines.
				result = append(result, line.path+"{"+canonicalName+nullable+"}")
				i++
				prefix := coalesceFieldPrefix(line.path)
				for i < len(lines) && strings.HasPrefix(lines[i].path, prefix) {
					i++
				}
				continue
			}

			// First occurrence — emit type intro and let fields be emitted normally.
			emittedTypes[canonicalName] = true
			result = append(result, line.path+"{"+canonicalName+nullable+"}")
			i++
			continue
		}

		// Regular line (primitive, null, undefined, empty, etc.).
		tv := line.typeVal
		nullable := ""
		if nullables[line.path] && tv != "undefined" && tv != "empty" {
			nullable = "?"
		}

		result = append(result, line.path+"{"+tv+nullable+"}")
		i++
	}

	return result
}

func coalesceFieldPrefix(path string) string {
	if path == "" {
		return "."
	}
	return path + "."
}
