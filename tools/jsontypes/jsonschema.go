package jsontypes

import (
	"encoding/json"
	"strings"
)

// GenerateJSONSchema converts formatted flat paths into a JSON Schema (draft 2020-12) document.
func GenerateJSONSchema(paths []string) string {
	types, _ := buildGoTypes(paths)

	typeMap := make(map[string]goType)
	for _, t := range types {
		typeMap[t.name] = t
	}

	if len(types) == 0 {
		return "{}\n"
	}

	root := types[0]
	defs := make(map[string]any)
	result := structToJSONSchema(root, typeMap, defs)
	result["$schema"] = "https://json-schema.org/draft/2020-12/schema"

	if len(defs) > 0 {
		result["$defs"] = defs
	}

	data, _ := json.MarshalIndent(result, "", "  ")
	return string(data) + "\n"
}

func structToJSONSchema(t goType, typeMap map[string]goType, defs map[string]any) map[string]any {
	props := make(map[string]any)
	var required []string

	for _, f := range t.fields {
		schema := goTypeToJSONSchema(f.goType, f.optional, typeMap, defs)
		props[f.jsonName] = schema
		if !f.optional {
			required = append(required, f.jsonName)
		}
	}

	result := map[string]any{
		"type":       "object",
		"properties": props,
	}
	if len(required) > 0 {
		result["required"] = required
	}
	return result
}

func goTypeToJSONSchema(goTyp string, nullable bool, typeMap map[string]goType, defs map[string]any) map[string]any {
	result := goTypeToJSONSchemaInner(goTyp, typeMap, defs)
	if nullable {
		// JSON Schema nullable: anyOf with null
		return map[string]any{
			"anyOf": []any{
				result,
				map[string]any{"type": "null"},
			},
		}
	}
	return result
}

func goTypeToJSONSchemaInner(goTyp string, typeMap map[string]goType, defs map[string]any) map[string]any {
	goTyp = strings.TrimPrefix(goTyp, "*")

	// Slice
	if strings.HasPrefix(goTyp, "[]") {
		elemType := goTyp[2:]
		return map[string]any{
			"type":  "array",
			"items": goTypeToJSONSchemaInner(elemType, typeMap, defs),
		}
	}

	// Map
	if strings.HasPrefix(goTyp, "map[string]") {
		valType := goTyp[11:]
		return map[string]any{
			"type":                 "object",
			"additionalProperties": goTypeToJSONSchemaInner(valType, typeMap, defs),
		}
	}

	// Primitives
	switch goTyp {
	case "string":
		return map[string]any{"type": "string"}
	case "int64":
		return map[string]any{"type": "integer"}
	case "float64":
		return map[string]any{"type": "number"}
	case "bool":
		return map[string]any{"type": "boolean"}
	case "any":
		return map[string]any{}
	}

	// Named struct — emit as $ref, add to $defs
	if t, ok := typeMap[goTyp]; ok {
		if _, exists := defs[goTyp]; !exists {
			defs[goTyp] = nil // placeholder
			defs[goTyp] = structToJSONSchema(t, typeMap, defs)
		}
		return map[string]any{"$ref": "#/$defs/" + goTyp}
	}

	return map[string]any{}
}
