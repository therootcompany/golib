package jsontypes

import (
	"encoding/json"
	"strings"
)

// generateTypedef converts formatted flat paths into a JSON Typedef (RFC 8927) document.
func GenerateTypedef(paths []string) string {
	types, _ := buildGoTypes(paths)

	typeMap := make(map[string]goType)
	for _, t := range types {
		typeMap[t.name] = t
	}

	// The first type is the root
	if len(types) == 0 {
		return "{}\n"
	}

	root := types[0]
	defs := make(map[string]any)
	result := structToJTD(root, typeMap, defs)

	if len(defs) > 0 {
		result["definitions"] = defs
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data) + "\n"
}

// structToJTD converts a goType to a JTD schema object.
func structToJTD(t goType, typeMap map[string]goType, defs map[string]any) map[string]any {
	props := make(map[string]any)
	optProps := make(map[string]any)

	for _, f := range t.fields {
		schema := goTypeToJTD(f.goType, f.optional, typeMap, defs)
		if f.optional {
			optProps[f.jsonName] = schema
		} else {
			props[f.jsonName] = schema
		}
	}

	result := make(map[string]any)
	if len(props) > 0 {
		result["properties"] = props
	} else if len(optProps) > 0 {
		// JTD requires "properties" if "optionalProperties" is present
		result["properties"] = map[string]any{}
	}
	if len(optProps) > 0 {
		result["optionalProperties"] = optProps
	}
	return result
}

// goTypeToJTD converts a Go type string to a JTD schema.
func goTypeToJTD(goTyp string, nullable bool, typeMap map[string]goType, defs map[string]any) map[string]any {
	result := goTypeToJTDInner(goTyp, typeMap, defs)
	if nullable {
		result["nullable"] = true
	}
	return result
}

func goTypeToJTDInner(goTyp string, typeMap map[string]goType, defs map[string]any) map[string]any {
	// Strip pointer
	goTyp = strings.TrimPrefix(goTyp, "*")

	// Slice
	if strings.HasPrefix(goTyp, "[]") {
		elemType := goTyp[2:]
		return map[string]any{
			"elements": goTypeToJTDInner(elemType, typeMap, defs),
		}
	}

	// Map
	if strings.HasPrefix(goTyp, "map[string]") {
		valType := goTyp[11:]
		return map[string]any{
			"values": goTypeToJTDInner(valType, typeMap, defs),
		}
	}

	// Primitives
	switch goTyp {
	case "string":
		return map[string]any{"type": "string"}
	case "int64":
		return map[string]any{"type": "int32"}
	case "float64":
		return map[string]any{"type": "float64"}
	case "bool":
		return map[string]any{"type": "boolean"}
	case "any":
		return map[string]any{}
	}

	// Named struct — emit as ref, add to definitions if not already there
	if t, ok := typeMap[goTyp]; ok {
		if _, exists := defs[goTyp]; !exists {
			// Add placeholder to prevent infinite recursion
			defs[goTyp] = nil
			defs[goTyp] = structToJTD(t, typeMap, defs)
		}
		return map[string]any{"ref": goTyp}
	}

	// Unknown type
	return map[string]any{}
}
