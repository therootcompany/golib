package jsontypes

import (
	"fmt"
	"strings"
)

// generateSQL converts formatted flat paths into SQL CREATE TABLE statements.
// Nested structs become separate tables with foreign key relationships.
// Arrays of structs get a join table or FK pointing back to the parent.
func GenerateSQL(paths []string) string {
	types, _ := buildGoTypes(paths)
	if len(types) == 0 {
		return ""
	}

	typeMap := make(map[string]goType)
	for _, t := range types {
		typeMap[t.name] = t
	}

	var buf strings.Builder

	// Emit in reverse order so referenced tables are created first.
	for i := len(types) - 1; i >= 0; i-- {
		t := types[i]
		if i < len(types)-1 {
			buf.WriteByte('\n')
		}
		tableName := toSnakeCase(t.name) + "s"
		buf.WriteString(fmt.Sprintf("CREATE TABLE %s (\n", tableName))
		buf.WriteString("  id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY")

		var fks []string
		for _, f := range t.fields {
			// Skip "id" — we generate a synthetic primary key
			if f.jsonName == "id" {
				continue
			}
			colType, fk := goTypeToSQL(f, tableName, typeMap)
			if colType == "" {
				continue // skip array-of-struct (handled via FK on child)
			}
			buf.WriteString(",\n")
			col := toSnakeCase(f.jsonName)
			if fk != "" {
				col += "_id"
			}
			if f.optional {
				buf.WriteString(fmt.Sprintf("  %s %s", col, colType))
			} else {
				buf.WriteString(fmt.Sprintf("  %s %s NOT NULL", col, colType))
			}
			if fk != "" {
				fks = append(fks, fk)
			}
		}

		for _, fk := range fks {
			buf.WriteString(",\n")
			buf.WriteString("  " + fk)
		}

		buf.WriteString("\n);\n")

		// For array-of-struct fields, add a FK column on the child table
		// pointing back to this parent.
		for _, f := range t.fields {
			childType := arrayElementType(f.goType)
			if childType == "" {
				continue
			}
			if _, isStruct := typeMap[childType]; !isStruct {
				continue
			}
			childTable := toSnakeCase(childType) + "s"
			parentFK := toSnakeCase(t.name) + "_id"
			buf.WriteString(fmt.Sprintf(
				"\nALTER TABLE %s ADD COLUMN %s BIGINT REFERENCES %s(id);\n",
				childTable, parentFK, tableName))
		}
	}

	return buf.String()
}

// goTypeToSQL returns (SQL column type, optional FK constraint string).
// Returns ("", "") for array-of-struct fields (handled separately).
func goTypeToSQL(f goField, parentTable string, typeMap map[string]goType) (string, string) {
	goTyp := strings.TrimPrefix(f.goType, "*")

	// Array of primitives → use array type or JSON
	if strings.HasPrefix(goTyp, "[]") {
		elemType := goTyp[2:]
		if _, isStruct := typeMap[elemType]; isStruct {
			return "", "" // handled via FK on child table
		}
		return "JSONB", ""
	}

	// Map → JSONB
	if strings.HasPrefix(goTyp, "map[") {
		return "JSONB", ""
	}

	// Named struct → FK reference
	if _, isStruct := typeMap[goTyp]; isStruct {
		refTable := toSnakeCase(goTyp) + "s"
		col := toSnakeCase(f.jsonName) + "_id"
		fk := fmt.Sprintf("CONSTRAINT fk_%s FOREIGN KEY (%s) REFERENCES %s(id)",
			col, col, refTable)
		return "BIGINT", fk
	}

	switch goTyp {
	case "string":
		return "TEXT", ""
	case "int64":
		return "BIGINT", ""
	case "float64":
		return "DOUBLE PRECISION", ""
	case "bool":
		return "BOOLEAN", ""
	case "any":
		return "JSONB", ""
	default:
		return "TEXT", ""
	}
}

// arrayElementType returns the element type if goTyp is []SomeType, else "".
func arrayElementType(goTyp string) string {
	goTyp = strings.TrimPrefix(goTyp, "*")
	if strings.HasPrefix(goTyp, "[]") {
		return goTyp[2:]
	}
	return ""
}

// toSnakeCase converts PascalCase to snake_case.
func toSnakeCase(s string) string {
	var buf strings.Builder
	for i, r := range s {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				buf.WriteByte('_')
			}
			buf.WriteRune(r + ('a' - 'A'))
		} else {
			buf.WriteRune(r)
		}
	}
	return buf.String()
}
