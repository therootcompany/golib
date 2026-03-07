package jsontypes

import (
	"fmt"
	"strings"
)

// generateZod converts formatted flat paths into Zod schema definitions.
func GenerateZod(paths []string) string {
	types, _ := buildGoTypes(paths)
	if len(types) == 0 {
		return ""
	}

	// Emit in reverse order so referenced schemas are defined first.
	var buf strings.Builder
	buf.WriteString("import { z } from \"zod\";\n\n")
	for i := len(types) - 1; i >= 0; i-- {
		t := types[i]
		if i < len(types)-1 {
			buf.WriteByte('\n')
		}
		buf.WriteString(fmt.Sprintf("export const %sSchema = z.object({\n", t.name))
		for _, f := range t.fields {
			zodType := goTypeToZod(f.goType)
			if f.optional {
				zodType += ".nullable().optional()"
			}
			buf.WriteString(fmt.Sprintf("  %s: %s,\n", f.jsonName, zodType))
		}
		buf.WriteString("});\n")
	}

	// Type aliases
	buf.WriteByte('\n')
	for _, t := range types {
		buf.WriteString(fmt.Sprintf("export type %s = z.infer<typeof %sSchema>;\n", t.name, t.name))
	}

	return buf.String()
}

func goTypeToZod(goTyp string) string {
	goTyp = strings.TrimPrefix(goTyp, "*")

	if strings.HasPrefix(goTyp, "[]") {
		return "z.array(" + goTypeToZod(goTyp[2:]) + ")"
	}
	if strings.HasPrefix(goTyp, "map[string]") {
		return "z.record(z.string(), " + goTypeToZod(goTyp[11:]) + ")"
	}

	switch goTyp {
	case "string":
		return "z.string()"
	case "int64":
		return "z.number().int()"
	case "float64":
		return "z.number()"
	case "bool":
		return "z.boolean()"
	case "any":
		return "z.unknown()"
	default:
		return goTyp + "Schema"
	}
}
