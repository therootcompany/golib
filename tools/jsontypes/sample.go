package jsontypes

import (
	"encoding/json"
	"fmt"
	"strings"
)

// Sample extracts one representative JSON sample for each distinct type
// (by key set) from a decoded JSON value. The output is a flat list of
// lines in the same path format as RawPaths, but with actual JSON values
// at leaf nodes and compact JSON samples at type intro lines.
//
// The value must have been decoded with json.Decoder.UseNumber().
func Sample(v any) []string {
	return SampleWithConfig(v, SampleConfig{})
}

// SampleConfig controls sample output.
type SampleConfig struct {
	// MaxStringLen truncates string values. 0 = no truncation.
	MaxStringLen int
}

// SampleWithConfig is like Sample but accepts configuration.
func SampleWithConfig(v any, cfg SampleConfig) []string {
	s := &sampler{maxStr: cfg.MaxStringLen}
	s.walk("", v)
	return Coalesce(s.paths)
}

type sampler struct {
	counter int
	paths   []string
	maxStr  int
}

func (s *sampler) emit(path string) {
	s.paths = append(s.paths, path)
}

func (s *sampler) nextName(path string) string {
	name := inferRawTypeName(path)
	id := s.counter
	s.counter++
	return fmt.Sprintf("%s%d", name, id)
}

func (s *sampler) walk(prefix string, v any) {
	switch val := v.(type) {
	case nil:
		s.emit(prefix + "{null}")
	case bool:
		s.emit(prefix + "{" + fmt.Sprintf("%v", val) + "}")
	case json.Number:
		s.emit(prefix + "{" + val.String() + "}")
	case string:
		s.emit(prefix + "{" + s.quotedString(val) + "}")
	case map[string]any:
		s.walkObject(prefix, val)
	case []any:
		s.walkArray(prefix, val)
	}
}

func (s *sampler) quotedString(val string) string {
	if s.maxStr > 0 && len(val) > s.maxStr {
		return fmt.Sprintf("%q", val[:s.maxStr]) + "..."
	}
	return fmt.Sprintf("%q", val)
}

func (s *sampler) walkObject(prefix string, obj map[string]any) {
	if len(obj) == 0 {
		s.emit(prefix + "{empty}")
		return
	}

	isMap, _ := looksLikeMap(obj)
	if isMap {
		s.walkMap(prefix, obj)
		return
	}

	s.walkStruct(prefix, []map[string]any{obj})
}

func (s *sampler) walkMap(prefix string, obj map[string]any) {
	keyName := inferKeyName(obj)
	mapPrefix := prefix + "[" + keyName + "]"
	values := make([]any, 0, len(obj))
	for _, v := range obj {
		values = append(values, v)
	}
	s.walkCollection(mapPrefix, values)
}

func (s *sampler) walkStruct(prefix string, instances []map[string]any) {
	merged := mergeObjects(instances)
	typeName := s.nextName(prefix)

	// Emit type intro with a compact JSON sample of the first instance.
	sample := s.compactSample(instances[0])
	s.emit(prefix + "{" + typeName + ":" + sample + "}")

	keys := sortedKeys(merged)
	for _, k := range keys {
		var fieldVals []any
		for _, inst := range instances {
			if v, ok := inst[k]; ok {
				fieldVals = append(fieldVals, v)
			} else {
				fieldVals = append(fieldVals, absentValue)
			}
		}
		s.walkCollection(joinPath(prefix, k), fieldVals)
	}
}

// compactSample creates a one-line JSON of an object with truncated values.
func (s *sampler) compactSample(obj map[string]any) string {
	keys := sortedKeys(obj)
	var parts []string
	for _, k := range keys {
		parts = append(parts, fmt.Sprintf("%q:%s", k, s.compactValue(obj[k])))
	}
	return "{" + strings.Join(parts, ",") + "}"
}

func (s *sampler) compactValue(v any) string {
	switch val := v.(type) {
	case nil:
		return "null"
	case bool:
		return fmt.Sprintf("%v", val)
	case json.Number:
		return val.String()
	case string:
		return s.quotedString(val)
	case map[string]any:
		return "{...}"
	case []any:
		if len(val) == 0 {
			return "[]"
		}
		return "[...]"
	default:
		return "?"
	}
}

func (s *sampler) walkArray(prefix string, arr []any) {
	if len(arr) == 0 {
		s.emit(prefix + "[]{empty}")
		return
	}

	if isTupleCandidate(arr) {
		for i, v := range arr {
			s.walk(fmt.Sprintf("%s[%d]", prefix, i), v)
		}
		return
	}

	s.walkCollection(prefix+"[]", arr)
}

func (s *sampler) walkCollection(prefix string, values []any) {
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

	if hasUndefined {
		s.emit(prefix + "{undefined}")
	}
	if hasNull {
		s.emit(prefix + "{null}")
	}

	for _, shape := range shapes {
		if len(shape.instances) == 1 {
			obj := shape.instances[0]
			isMap, _ := looksLikeMap(obj)
			if isMap {
				s.walkMap(prefix, obj)
				continue
			}
		}
		s.walkStruct(prefix, shape.instances)
	}

	// Emit one sample per primitive type (not per value).
	seen := make(map[string]bool) // keyed by kind: "number", "string", "bool"
	for _, v := range nonObjects {
		switch val := v.(type) {
		case json.Number:
			if !seen["number"] {
				seen["number"] = true
				s.emit(prefix + "{" + val.String() + "}")
			}
		case string:
			if !seen["string"] {
				seen["string"] = true
				s.emit(prefix + "{" + s.quotedString(val) + "}")
			}
		case bool:
			if !seen["bool"] {
				seen["bool"] = true
				s.emit(prefix + "{" + fmt.Sprintf("%v", val) + "}")
			}
		case []any:
			if !seen["array"] {
				seen["array"] = true
				s.walkArray(prefix, val)
			}
		}
	}

	if !hasNull && !hasUndefined && len(shapes) == 0 && len(nonObjects) == 0 {
		s.emit(prefix + "{empty}")
	}
}
