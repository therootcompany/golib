package jsontypes

import (
	"fmt"
	"strings"
)

// generateJSDoc converts formatted flat paths into JSDoc @typedef annotations.
func GenerateJSDoc(paths []string) string {
	types, _ := buildGoTypes(paths)
	if len(types) == 0 {
		return ""
	}

	var buf strings.Builder
	for i, t := range types {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(fmt.Sprintf("/**\n * @typedef {Object} %s\n", t.name))
		for _, f := range t.fields {
			jsType := goTypeToJSDoc(f.goType)
			if f.optional {
				buf.WriteString(fmt.Sprintf(" * @property {%s} [%s]\n", jsType, f.jsonName))
			} else {
				buf.WriteString(fmt.Sprintf(" * @property {%s} %s\n", jsType, f.jsonName))
			}
		}
		buf.WriteString(" */\n")
	}
	return buf.String()
}

func goTypeToJSDoc(goTyp string) string {
	goTyp = strings.TrimPrefix(goTyp, "*")

	if strings.HasPrefix(goTyp, "[]") {
		return goTypeToJSDoc(goTyp[2:]) + "[]"
	}
	if strings.HasPrefix(goTyp, "map[string]") {
		return "Object<string, " + goTypeToJSDoc(goTyp[11:]) + ">"
	}

	switch goTyp {
	case "string":
		return "string"
	case "int64", "float64":
		return "number"
	case "bool":
		return "boolean"
	case "any":
		return "*"
	default:
		return goTyp
	}
}
