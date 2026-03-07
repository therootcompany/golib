package jsontypes

import (
	"fmt"
	"sort"
	"strings"
)

// decideMapOrStruct determines whether an object is a map or struct.
// In anonymous mode, uses heuristics silently.
// Otherwise, shows a combined prompt: enter a TypeName or 'm' for map.
// In default mode, confident heuristic maps skip the prompt.
// In askTypes mode, the prompt is always shown.
func (a *Analyzer) decideMapOrStruct(path string, obj map[string]any) bool {
	isMap, confident := looksLikeMap(obj)
	if a.anonymous {
		return isMap
	}

	// Default mode: skip prompt when heuristics are confident
	if !a.askTypes && confident {
		return isMap
	}

	return a.promptMapOrStructWithName(path, obj, isMap, confident)
}

// promptMapOrStructWithName shows the object's fields and asks a combined question.
// The user can type 'm' or 'map' for a map, a name starting with a capital letter
// for a struct type, or press Enter to accept the default.
func (a *Analyzer) promptMapOrStructWithName(path string, obj map[string]any, heuristicMap, confident bool) bool {
	keys := sortedKeys(obj)

	inferred := inferTypeName(path)
	if inferred == "" {
		a.typeCounter++
		inferred = fmt.Sprintf("Struct%d", a.typeCounter)
	}

	defaultVal := inferred
	if confident && heuristicMap {
		defaultVal = "m"
	}

	fmt.Fprintf(a.Prompter.output, "\nAt %s\n", shortPath(path))
	fmt.Fprintf(a.Prompter.output, "  Object with %d keys:\n", len(keys))
	for _, k := range keys {
		fmt.Fprintf(a.Prompter.output, "    %s: %s\n", k, valueSummary(obj[k]))
	}

	answer := a.Prompter.askMapOrName("Struct name (or 'm' for map)?", defaultVal)
	if answer == "m" {
		a.pendingTypeName = ""
		return true
	}
	a.pendingTypeName = answer
	return false
}

// decideKeyName infers the map key type from the keys.
func (a *Analyzer) decideKeyName(_ string, obj map[string]any) string {
	return inferKeyName(obj)
}

// decideTypeName determines the struct type name, using inference and optionally
// prompting the user.
func (a *Analyzer) decideTypeName(path string, obj map[string]any) string {
	// Check if we've already named a type with this exact shape
	sig := shapeSignature(obj)
	if existing, ok := a.knownTypes[sig]; ok {
		a.pendingTypeName = ""
		return existing.name
	}

	newFields := fieldSet(obj)

	// Consume pending name from askTypes combined prompt
	if a.pendingTypeName != "" {
		name := a.pendingTypeName
		a.pendingTypeName = ""
		return a.resolveTypeName(path, name, newFields, sig)
	}

	inferred := inferTypeName(path)
	if inferred == "" {
		a.typeCounter++
		inferred = fmt.Sprintf("Struct%d", a.typeCounter)
	}

	// Default and anonymous modes: auto-resolve without prompting
	if !a.askTypes {
		return a.autoResolveTypeName(path, inferred, newFields, sig)
	}

	// askTypes mode: show fields and prompt for name
	keys := sortedKeys(obj)
	fmt.Fprintf(a.Prompter.output, "\nAt %s\n", shortPath(path))
	fmt.Fprintf(a.Prompter.output, "  Struct with %d fields:\n", len(keys))
	for _, k := range keys {
		fmt.Fprintf(a.Prompter.output, "    %s: %s\n", k, valueSummary(obj[k]))
	}

	name := a.promptName(path, inferred, newFields, sig)
	return name
}

// autoResolveTypeName registers or resolves a type name without prompting.
// On collision, tries the parent-prefix strategy; if that also collides, prompts
// (unless anonymous, in which case it uses a numbered fallback).
func (a *Analyzer) autoResolveTypeName(path, name string, newFields map[string]string, sig string) string {
	existing, taken := a.typesByName[name]
	if !taken {
		return a.registerType(sig, name, newFields)
	}

	rel := fieldRelation(existing.fields, newFields)
	switch rel {
	case relEqual:
		a.knownTypes[sig] = existing
		return name
	case relSubset, relSuperset:
		merged := mergeFieldSets(existing.fields, newFields)
		existing.fields = merged
		a.knownTypes[sig] = existing
		return name
	default:
		// Collision — try parent-prefix strategy
		alt := a.suggestAlternativeName(path, name)
		if _, altTaken := a.typesByName[alt]; !altTaken {
			return a.registerType(sig, alt, newFields)
		}
		// Parent strategy also taken
		if a.anonymous {
			a.typeCounter++
			return a.registerType(sig, fmt.Sprintf("%s%d", name, a.typeCounter), newFields)
		}
		// Last resort: prompt
		return a.promptName(path, alt, newFields, sig)
	}
}

// resolveTypeName handles a name that came from the combined prompt,
// checking for collisions with existing types.
func (a *Analyzer) resolveTypeName(path, name string, newFields map[string]string, sig string) string {
	existing, taken := a.typesByName[name]
	if !taken {
		return a.registerType(sig, name, newFields)
	}

	rel := fieldRelation(existing.fields, newFields)
	switch rel {
	case relEqual:
		a.knownTypes[sig] = existing
		return name
	case relSubset, relSuperset:
		merged := mergeFieldSets(existing.fields, newFields)
		existing.fields = merged
		a.knownTypes[sig] = existing
		return name
	default:
		return a.promptName(path, name, newFields, sig)
	}
}

// promptName asks for a type name and handles collisions with existing types.
// Pre-resolves the suggested name so the user sees a valid default.
func (a *Analyzer) promptName(path, suggested string, newFields map[string]string, sig string) string {
	suggested = a.preResolveCollision(path, suggested, newFields, sig)

	for {
		name := a.Prompter.askFreeform("Name for this type?", suggested)

		existing, taken := a.typesByName[name]
		if !taken {
			return a.registerType(sig, name, newFields)
		}

		rel := fieldRelation(existing.fields, newFields)
		switch rel {
		case relEqual:
			a.knownTypes[sig] = existing
			return name
		case relSubset, relSuperset:
			fmt.Fprintf(a.Prompter.output, "  Extending existing type %q (merging fields)\n", name)
			merged := mergeFieldSets(existing.fields, newFields)
			existing.fields = merged
			a.knownTypes[sig] = existing
			return name
		case relOverlap:
			fmt.Fprintf(a.Prompter.output, "  Type %q already exists with overlapping fields: %s\n",
				name, fieldList(existing.fields))
			choice := a.Prompter.ask(
				fmt.Sprintf("  [e]xtend %q with merged fields, or use a [d]ifferent name?", name),
				"e", []string{"e", "d"},
			)
			if choice == "e" {
				merged := mergeFieldSets(existing.fields, newFields)
				existing.fields = merged
				a.knownTypes[sig] = existing
				return name
			}
			suggested = a.suggestAlternativeName(path, name)
			continue
		case relDisjoint:
			fmt.Fprintf(a.Prompter.output, "  Type %q already exists with different fields: %s\n",
				name, fieldList(existing.fields))
			suggested = a.suggestAlternativeName(path, name)
			continue
		}
	}
}

// preResolveCollision checks if the suggested name collides with an existing
// type that can't be auto-merged. If so, prints a warning and returns a new
// suggested name.
func (a *Analyzer) preResolveCollision(path, suggested string, newFields map[string]string, sig string) string {
	existing, taken := a.typesByName[suggested]
	if !taken {
		return suggested
	}

	rel := fieldRelation(existing.fields, newFields)
	switch rel {
	case relEqual, relSubset, relSuperset:
		return suggested
	default:
		alt := a.suggestAlternativeName(path, suggested)
		fmt.Fprintf(a.Prompter.output, "  (type %q already exists with different fields, suggesting %q)\n",
			suggested, alt)
		return alt
	}
}

// suggestAlternativeName generates a better name when a collision occurs,
// using the parent type as a prefix (e.g., "DocumentRoom" instead of "Room2").
func (a *Analyzer) suggestAlternativeName(path, collided string) string {
	parent := parentTypeName(path)
	if parent != "" {
		candidate := parent + collided
		if _, taken := a.typesByName[candidate]; !taken {
			return candidate
		}
	}
	// Fall back to numbered suffix
	a.typeCounter++
	return fmt.Sprintf("%s%d", collided, a.typeCounter)
}

// shortPath returns the full path but with only the most recent {Type}
// annotation kept; all earlier type annotations are stripped. e.g.:
// ".{RoomsResult}.rooms[]{Room}.room[string][]{RoomRoom}.json{RoomRoomJSON}.feature_types[]"
// → ".rooms[].room[string][].json{RoomRoomJSON}.feature_types[]"
func shortPath(path string) string {
	// Find the last {Type} annotation
	lastOpen := -1
	lastClose := -1
	for i := len(path) - 1; i >= 0; i-- {
		if path[i] == '}' && lastClose < 0 {
			lastClose = i
		}
		if path[i] == '{' && lastClose >= 0 && lastOpen < 0 {
			lastOpen = i
			break
		}
	}
	if lastOpen < 0 {
		return path
	}

	// Rebuild: strip all {Type} annotations except the last one
	var buf strings.Builder
	i := 0
	for i < len(path) {
		if path[i] == '{' {
			end := strings.IndexByte(path[i:], '}')
			if end < 0 {
				break
			}
			if i == lastOpen {
				// Keep this annotation
				buf.WriteString(path[i : i+end+1])
			}
			i = i + end + 1
		} else {
			buf.WriteByte(path[i])
			i++
		}
	}

	// Collapse any double dots left by stripping (e.g., ".." → ".")
	return strings.ReplaceAll(buf.String(), "..", ".")
}

// parentTypeName extracts the most recent {TypeName} from a path.
// e.g., ".[id]{Document}.rooms[int]{Room}.details" → "Room"
func parentTypeName(path string) string {
	last := ""
	for {
		idx := strings.Index(path, "{")
		if idx < 0 {
			break
		}
		end := strings.Index(path[idx:], "}")
		if end < 0 {
			break
		}
		candidate := path[idx+1 : idx+end]
		if candidate != "null" {
			last = candidate
		}
		path = path[idx+end+1:]
	}
	return last
}

func (a *Analyzer) registerType(sig, name string, fields map[string]string) string {
	st := &structType{name: name, fields: fields}
	a.knownTypes[sig] = st
	a.typesByName[name] = st
	return name
}

type fieldRelationType int

const (
	relEqual    fieldRelationType = iota
	relSubset                     // existing ⊂ new
	relSuperset                   // existing ⊃ new
	relOverlap                    // some shared, some unique to each
	relDisjoint                   // no fields in common
)

func fieldRelation(a, b map[string]string) fieldRelationType {
	aInB, bInA := 0, 0
	for k, ak := range a {
		if bk, ok := b[k]; ok && kindsCompatible(ak, bk) {
			aInB++
		}
	}
	for k, bk := range b {
		if ak, ok := a[k]; ok && kindsCompatible(ak, bk) {
			bInA++
		}
	}
	shared := aInB // same as bInA
	if shared == 0 {
		return relDisjoint
	}
	if shared == len(a) && shared == len(b) {
		return relEqual
	}
	if shared == len(a) {
		return relSubset // all of a is in b, b has more
	}
	if shared == len(b) {
		return relSuperset // all of b is in a, a has more
	}
	return relOverlap
}

// kindsCompatible returns true if two field value kinds can be considered the
// same type. "null" is compatible with anything (it's just an absent value),
// and "mixed" is compatible with anything.
func kindsCompatible(a, b string) bool {
	if a == b {
		return true
	}
	if a == "null" || b == "null" || a == "mixed" || b == "mixed" {
		return true
	}
	return false
}

// fieldsOverlap returns true if one field set is a subset or superset of the other.
func fieldsOverlap(a, b map[string]string) bool {
	rel := fieldRelation(a, b)
	return rel == relEqual || rel == relSubset || rel == relSuperset
}

func mergeFieldSets(a, b map[string]string) map[string]string {
	merged := make(map[string]string, len(a)+len(b))
	for k, v := range a {
		merged[k] = v
	}
	for k, v := range b {
		if existing, ok := merged[k]; ok && existing != v {
			merged[k] = "mixed"
		} else {
			merged[k] = v
		}
	}
	return merged
}

func fieldList(fields map[string]string) string {
	keys := make([]string, 0, len(fields))
	for k := range fields {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return strings.Join(keys, ", ")
}

// decideTupleOrList asks the user if a short mixed-type array is a tuple or list.
func (a *Analyzer) decideTupleOrList(path string, arr []any) bool {
	if a.anonymous {
		return false // default to list
	}
	fmt.Fprintf(a.Prompter.output, "\nAt %s\n", shortPath(path))
	fmt.Fprintf(a.Prompter.output, "  Short array with %d elements of mixed types:\n", len(arr))
	for i, v := range arr {
		fmt.Fprintf(a.Prompter.output, "    [%d]: %s\n", i, valueSummary(v))
	}
	choice := a.Prompter.ask(
		"Is this a [l]ist or a [t]uple?",
		"l", []string{"l", "t"},
	)
	return choice == "t"
}

// valueSummary returns a short human-readable summary of a JSON value.
func valueSummary(v any) string {
	switch tv := v.(type) {
	case nil:
		return "null"
	case bool:
		return fmt.Sprintf("%v", tv)
	case string:
		if len(tv) > 40 {
			return fmt.Sprintf("%q...", tv[:37])
		}
		return fmt.Sprintf("%q", tv)
	case []any:
		if len(tv) == 0 {
			return "[]"
		}
		return fmt.Sprintf("[...] (%d elements)", len(tv))
	case map[string]any:
		if len(tv) == 0 {
			return "{}"
		}
		keys := sortedKeys(tv)
		preview := keys
		if len(preview) > 3 {
			preview = preview[:3]
		}
		s := "{" + strings.Join(preview, ", ")
		if len(keys) > 3 {
			s += ", ..."
		}
		return s + "}"
	default:
		return fmt.Sprintf("%v", v)
	}
}

func fieldSet(obj map[string]any) map[string]string {
	fs := make(map[string]string, len(obj))
	for k, v := range obj {
		fs[k] = kindOf(v)
	}
	return fs
}
