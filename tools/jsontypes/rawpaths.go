package jsontypes

import (
	"encoding/json"
	"fmt"
	"strings"
)

// RawPaths walks a decoded JSON value depth-first and emits flat paths with
// monotonically numbered type names. Every struct shape gets a unique name
// derived from its parent path segment and a global counter (e.g., Root0,
// People2, People3). Type intros appear immediately before their fields,
// making the output streamable and order-stable.
//
// The value must have been decoded with json.Decoder.UseNumber() so that
// integers and floats are distinguishable.
func RawPaths(v any) []string {
	w := &rawWalker{}
	w.walk("", v)
	return w.paths
}

type rawWalker struct {
	counter int
	paths   []string
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
		w.emit(prefix + "{bool}")
	case json.Number:
		if _, err := val.Int64(); err == nil {
			w.emit(prefix + "{int}")
		} else {
			w.emit(prefix + "{float}")
		}
	case string:
		w.emit(prefix + "{string}")
	case map[string]any:
		w.walkObject(prefix, val)
	case []any:
		w.walkArray(prefix, val)
	}
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
				fieldVals = append(fieldVals, nil)
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
	// Separate by kind: objects, primitives/arrays, nulls.
	type shapeInstances struct {
		sig       string
		instances []map[string]any
	}
	var shapes []shapeInstances
	shapeIndex := make(map[string]int)
	hasNull := false
	var nonObjects []any

	for _, v := range values {
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

	// Emit null if seen.
	if hasNull {
		w.emit(prefix + "{null}")
	}

	// Emit each object shape. If a shape has exactly one instance and it
	// looks like a map, walk it as a map instead of a struct.
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

	// Emit primitive/array types (deduplicated).
	seen := make(map[string]bool)
	for _, v := range nonObjects {
		switch val := v.(type) {
		case json.Number:
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
		case string:
			if !seen["string"] {
				seen["string"] = true
				w.emit(prefix + "{string}")
			}
		case bool:
			if !seen["bool"] {
				seen["bool"] = true
				w.emit(prefix + "{bool}")
			}
		case []any:
			// Nested arrays — walk once.
			if !seen["array"] {
				seen["array"] = true
				w.walkArray(prefix, val)
			}
		}
	}

	// If nothing was emitted (all nils, empty), emit any.
	if !hasNull && len(shapes) == 0 && len(nonObjects) == 0 {
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
