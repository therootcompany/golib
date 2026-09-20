package jsontypes

import (
	"fmt"
	"strings"
)

// GenerateTypeScript converts formatted flat paths into TypeScript interface definitions.
func GenerateTypeScript(paths []string) string {
	types, _ := buildGoTypes(paths)
	if len(types) == 0 {
		return ""
	}

	var buf strings.Builder
	for i, t := range types {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(fmt.Sprintf("export interface %s {\n", t.name))
		for _, f := range t.fields {
			tsType := goTypeToTS(f.goType)
			if f.optional {
				buf.WriteString(fmt.Sprintf("  %s?: %s | null;\n", f.jsonName, tsType))
			} else {
				buf.WriteString(fmt.Sprintf("  %s: %s;\n", f.jsonName, tsType))
			}
		}
		buf.WriteString("}\n")
	}
	return buf.String()
}

func goTypeToTS(goTyp string) string {
	goTyp = strings.TrimPrefix(goTyp, "*")

	if strings.HasPrefix(goTyp, "[]") {
		return goTypeToTS(goTyp[2:]) + "[]"
	}
	if strings.HasPrefix(goTyp, "map[string]") {
		return "Record<string, " + goTypeToTS(goTyp[11:]) + ">"
	}

	switch goTyp {
	case "string":
		return "string"
	case "int64", "float64":
		return "number"
	case "bool":
		return "boolean"
	case "any":
		return "unknown"
	default:
		return goTyp
	}
}
