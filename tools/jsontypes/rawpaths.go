package jsontypes

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RawPathsConfig controls raw path output.
type RawPathsConfig struct {
	// SampleLen, when > 0, emits a truncated sample value instead of a
	// type name at leaf nodes. E.g., {string} becomes {"Alice Anglerso..."}.
	// The type is implicit from the value representation.
	SampleLen int
}

// RawPaths walks a decoded JSON value depth-first and emits flat paths with
// monotonically numbered type names. Every struct shape gets a unique name
// derived from its parent path segment and a global counter (e.g., Root0,
// People2, People3). Type intros appear immediately before their fields,
// making the output streamable and order-stable.
//
// The value must have been decoded with json.Decoder.UseNumber() so that
// integers and floats are distinguishable.
func RawPaths(v any) []string {
	return RawPathsWithConfig(v, RawPathsConfig{})
}

// RawPathsWithConfig is like RawPaths but accepts configuration.
func RawPathsWithConfig(v any, cfg RawPathsConfig) []string {
	w := &rawWalker{sampleLen: cfg.SampleLen}
	w.walk("", v)
	return w.paths
}

type rawWalker struct {
	counter   int
	paths     []string
	sampleLen int
}

func (w *rawWalker) emit(path string) {
	w.paths = append(w.paths, path)
}

func (w *rawWalker) nextName(path string) string {
	name := inferRawTypeName(path)
	id := w.counter
	w.counter++
	return fmt.Sprintf("%s%d", name, id)
}

func (w *rawWalker) walk(prefix string, v any) {
	switch val := v.(type) {
	case nil:
		w.emit(prefix + "{null}")
	case bool:
		if w.sampleLen > 0 {
			w.emit(prefix + "{" + fmt.Sprintf("%v", val) + "}")
		} else {
			w.emit(prefix + "{bool}")
		}
	case json.Number:
		if w.sampleLen > 0 {
			w.emit(prefix + "{" + val.String() + "}")
		} else if _, err := val.Int64(); err == nil {
			w.emit(prefix + "{int}")
		} else {
			w.emit(prefix + "{float}")
		}
	case string:
		if w.sampleLen > 0 {
			w.emit(prefix + "{" + truncateQuoted(val, w.sampleLen) + "}")
		} else {
			w.emit(prefix + "{string}")
		}
	case map[string]any:
		w.walkObject(prefix, val)
	case []any:
		w.walkArray(prefix, val)
	}
}

// truncateQuoted returns a JSON-quoted string, truncated with "..." if needed.
func truncateQuoted(s string, maxLen int) string {
	if len(s) <= maxLen {
		return fmt.Sprintf("%q", s)
	}
	return fmt.Sprintf("%q", s[:maxLen]) + "..."
}

func (w *rawWalker) walkObject(prefix string, obj map[string]any) {
	if len(obj) == 0 {
		w.emit(prefix + "{empty}")
		return
	}

	isMap, _ := looksLikeMap(obj)
	if isMap {
		w.walkMap(prefix, obj)
		return
	}

	w.walkStruct(prefix, []map[string]any{obj})
}

func (w *rawWalker) walkMap(prefix string, obj map[string]any) {
	keyName := inferKeyName(obj)
	mapPrefix := prefix + "[" + keyName + "]"

	// Collect all values and walk as a collection.
	values := make([]any, 0, len(obj))
	for _, v := range obj {
		values = append(values, v)
	}
	w.walkCollection(mapPrefix, values)
}

// absentValue is a sentinel distinct from nil (JSON null) to represent
// a field that was absent from a struct instance.
var absentValue = &struct{}{}

func (w *rawWalker) walkStruct(prefix string, instances []map[string]any) {
	merged := mergeObjects(instances)
	typeName := w.nextName(prefix)

	// Emit type intro with the type name.
	w.emit(prefix + "{" + typeName + "}")

	// Fields use the bare prefix (without the type name) since
	// the type was already declared on the intro line above.
	keys := sortedKeys(merged)
	for _, k := range keys {
		// Collect all values for this field across instances.
		var fieldVals []any
		for _, inst := range instances {
			if v, ok := inst[k]; ok {
				fieldVals = append(fieldVals, v)
			} else {
				fieldVals = append(fieldVals, absentValue)
			}
		}
		w.walkCollection(joinPath(prefix, k), fieldVals)
	}
}

func (w *rawWalker) walkArray(prefix string, arr []any) {
	if len(arr) == 0 {
		w.emit(prefix + "[]{empty}")
		return
	}

	if isTupleCandidate(arr) {
		w.walkTuple(prefix, arr)
		return
	}

	w.walkCollection(prefix+"[]", arr)
}

func (w *rawWalker) walkTuple(prefix string, arr []any) {
	for i, v := range arr {
		w.walk(fmt.Sprintf("%s[%d]", prefix, i), v)
	}
}

// walkCollection handles multiple values at the same path position (array
// elements, map values, or field values across struct instances). It groups
// objects by shape and walks each shape separately.
func (w *rawWalker) walkCollection(prefix string, values []any) {
	// Separate by kind: objects, primitives/arrays, nulls, absent.
	type shapeInstances struct {
		sig       string
		instances []map[string]any
	}
	var shapes []shapeInstances
	shapeIndex := make(map[string]int)
	hasNull := false
	hasUndefined := false
	var nonObjects []any

	for _, v := range values {
		if v == absentValue {
			hasUndefined = true
			continue
		}
		switch val := v.(type) {
		case nil:
			hasNull = true
		case map[string]any:
			sig := shapeSignature(val)
			if idx, ok := shapeIndex[sig]; ok {
				shapes[idx].instances = append(shapes[idx].instances, val)
			} else {
				shapeIndex[sig] = len(shapes)
				shapes = append(shapes, shapeInstances{sig, []map[string]any{val}})
			}
		default:
			nonObjects = append(nonObjects, val)
		}
	}

	// Emit undefined (field absent) and null (field present with null value).
	if hasUndefined {
		w.emit(prefix + "{undefined}")
	}
	if hasNull {
		w.emit(prefix + "{null}")
	}

	// If multiple shapes share a common core (≥ 2 keys in > 50% of objects),
	// treat them as one struct with optional fields.
	if len(shapes) > 1 {
		var allObjs []map[string]any
		for _, s := range shapes {
			allObjs = append(allObjs, s.instances...)
		}
		if shouldMergeObjects(allObjs) {
			// Merge all into one struct — absent fields become optional.
			w.walkStruct(prefix, allObjs)
		} else {
			// No common core — emit each shape separately.
			for _, shape := range shapes {
				if len(shape.instances) == 1 {
					obj := shape.instances[0]
					isMap, _ := looksLikeMap(obj)
					if isMap {
						w.walkMap(prefix, obj)
						continue
					}
				}
				w.walkStruct(prefix, shape.instances)
			}
		}
	} else {
		// Single shape (or none) — emit directly.
		for _, shape := range shapes {
			if len(shape.instances) == 1 {
				obj := shape.instances[0]
				isMap, _ := looksLikeMap(obj)
				if isMap {
					w.walkMap(prefix, obj)
					continue
				}
			}
			w.walkStruct(prefix, shape.instances)
		}
	}

	// Emit primitive/array types (deduplicated).
	seen := make(map[string]bool)
	for _, v := range nonObjects {
		switch val := v.(type) {
		case json.Number:
			if w.sampleLen > 0 {
				sample := val.String()
				if !seen[sample] {
					seen[sample] = true
					w.emit(prefix + "{" + sample + "}")
				}
			} else {
				var typ string
				if _, err := val.Int64(); err == nil {
					typ = "int"
				} else {
					typ = "float"
				}
				if !seen[typ] {
					seen[typ] = true
					w.emit(prefix + "{" + typ + "}")
				}
			}
		case string:
			if w.sampleLen > 0 {
				sample := truncateQuoted(val, w.sampleLen)
				if !seen[sample] {
					seen[sample] = true
					w.emit(prefix + "{" + sample + "}")
				}
			} else {
				if !seen["string"] {
					seen["string"] = true
					w.emit(prefix + "{string}")
				}
			}
		case bool:
			if w.sampleLen > 0 {
				sample := fmt.Sprintf("%v", val)
				if !seen[sample] {
					seen[sample] = true
					w.emit(prefix + "{" + sample + "}")
				}
			} else {
				if !seen["bool"] {
					seen["bool"] = true
					w.emit(prefix + "{bool}")
				}
			}
		case []any:
			// Nested arrays — walk once.
			if !seen["array"] {
				seen["array"] = true
				w.walkArray(prefix, val)
			}
		}
	}

	// If nothing was emitted (all absent/nils, empty), emit empty.
	if !hasNull && !hasUndefined && len(shapes) == 0 && len(nonObjects) == 0 {
		w.emit(prefix + "{empty}")
	}
}

// inferRawTypeName produces a simple type name for raw paths.
// Collection elements get "<Name>Item" (e.g., friends[] → FriendsItem).
// Direct fields use PascalCase as-is (e.g., address → Address).
func inferRawTypeName(path string) string {
	if path == "" {
		return "Root"
	}

	// Detect collection context: path ends with [], [string], [int], etc.
	isCollection := strings.HasSuffix(path, "[]") ||
		(strings.Contains(path, "[") && strings.HasSuffix(path, "]"))

	parts := strings.FieldsFunc(path, func(r rune) bool {
		return r == '.' || r == '[' || r == ']' || r == '{' || r == '}'
	})
	if len(parts) == 0 {
		if isCollection {
			return "RootItem"
		}
		return "Root"
	}

	last := parts[len(parts)-1]
	// Skip index-like segments to get the field name.
	if last == "int" || last == "string" || last == "id" {
		if len(parts) >= 2 {
			last = parts[len(parts)-2]
		} else {
			return "RootItem"
		}
	}

	name := snakeToPascal(last)
	if isCollection {
		name += "Item"
	}

	// If the name is too generic, prepend the parent.
	if canonical, ok := ambiguousTypeNames[strings.ToLower(name)]; ok {
		parent := parentTypeName(path)
		if parent != "" {
			if isCollection {
				return parent + canonical + "Item"
			}
			return parent + canonical
		}
	}

	return name
}

// joinPath appends a field name to a path prefix with a dot separator.
func joinPath(prefix, field string) string {
	if prefix == "" {
		return "." + field
	}
	return prefix + "." + field
}

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
