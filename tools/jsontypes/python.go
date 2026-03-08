package jsontypes

import (
	"fmt"
	"strings"
)

// GeneratePython converts formatted flat paths into Python TypedDict definitions.
func GeneratePython(paths []string) string {
	types, _ := buildGoTypes(paths)
	if len(types) == 0 {
		return ""
	}

	hasOptional := false
	for _, t := range types {
		for _, f := range t.fields {
			if f.optional {
				hasOptional = true
				break
			}
		}
		if hasOptional {
			break
		}
	}

	var buf strings.Builder
	buf.WriteString("from __future__ import annotations\n\n")
	if hasOptional {
		buf.WriteString("from typing import NotRequired, TypedDict\n")
	} else {
		buf.WriteString("from typing import TypedDict\n")
	}

	// Emit in reverse so referenced types come first.
	for i := len(types) - 1; i >= 0; i-- {
		t := types[i]
		buf.WriteString(fmt.Sprintf("\n\nclass %s(TypedDict):\n", t.name))
		if len(t.fields) == 0 {
			buf.WriteString("    pass\n")
			continue
		}
		for _, f := range t.fields {
			pyType := goTypeToPython(f.goType)
			if f.optional {
				buf.WriteString(fmt.Sprintf("    %s: NotRequired[%s | None]\n", f.jsonName, pyType))
			} else {
				buf.WriteString(fmt.Sprintf("    %s: %s\n", f.jsonName, pyType))
			}
		}
	}
	return buf.String()
}

func goTypeToPython(goTyp string) string {
	goTyp = strings.TrimPrefix(goTyp, "*")

	if strings.HasPrefix(goTyp, "[]") {
		return "list[" + goTypeToPython(goTyp[2:]) + "]"
	}
	if strings.HasPrefix(goTyp, "map[string]") {
		return "dict[str, " + goTypeToPython(goTyp[11:]) + "]"
	}

	switch goTyp {
	case "string":
		return "str"
	case "int64":
		return "int"
	case "float64":
		return "float"
	case "bool":
		return "bool"
	case "any":
		return "object"
	default:
		return goTyp
	}
}
