package jsontypes

import (
	"fmt"
	"sort"
	"strings"
)

// goType represents a Go struct being built from flat paths.
type goType struct {
	name   string
	fields []goField
}

type goField struct {
	goName   string // PascalCase Go field name
	jsonName string // original JSON key
	goType   string // Go type string
	optional bool   // nullable/optional field
}

// goUnion represents a discriminated union — multiple concrete struct types
// at the same JSON position (e.g., an array with different shaped objects).
type goUnion struct {
	name          string              // interface name, e.g., "Item"
	concreteTypes []string            // ordered concrete type names
	sharedFields  []goField           // fields common to ALL concrete types
	uniqueFields  map[string][]string // typeName → json field names unique to it
	typeFieldJSON string              // "type"/"kind" if present in shared, else ""
	index         string              // "[]", "[string]", etc.
	fieldName     string              // json field name in parent struct
}

func (u *goUnion) markerMethod() string {
	return "is" + u.name
}

func (u *goUnion) unmarshalFuncName() string {
	return "unmarshal" + u.name
}

func (u *goUnion) wrapperTypeName() string {
	if u.index == "[]" {
		return u.name + "Slice"
	}
	if strings.HasPrefix(u.index, "[") {
		return u.name + "Map"
	}
	return u.name
}

// generateGoStructs converts formatted flat paths into Go struct definitions
// with json tags. When multiple types share an array/map position, it generates
// a sealed interface, discriminator function, and wrapper type.
func GenerateGoStructs(paths []string) string {
	types, unions := buildGoTypes(paths)

	var buf strings.Builder

	if len(unions) > 0 {
		buf.WriteString("import (\n\t\"encoding/json\"\n\t\"fmt\"\n)\n\n")
	}

	for i, t := range types {
		if i > 0 {
			buf.WriteByte('\n')
		}
		buf.WriteString(fmt.Sprintf("type %s struct {\n", t.name))
		maxNameLen := 0
		maxTypeLen := 0
		for _, f := range t.fields {
			if len(f.goName) > maxNameLen {
				maxNameLen = len(f.goName)
			}
			if len(f.goType) > maxTypeLen {
				maxTypeLen = len(f.goType)
			}
		}
		for _, f := range t.fields {
			tag := fmt.Sprintf("`json:\"%s\"`", f.jsonName)
			if f.optional {
				tag = fmt.Sprintf("`json:\"%s,omitempty\"`", f.jsonName)
			}
			buf.WriteString(fmt.Sprintf("\t%-*s %-*s %s\n",
				maxNameLen, f.goName,
				maxTypeLen, f.goType,
				tag))
		}
		buf.WriteString("}\n")
	}

	for _, u := range unions {
		buf.WriteByte('\n')
		writeUnionCode(&buf, u)
	}

	return buf.String()
}

// buildGoTypes parses the formatted paths and groups fields by type.
// It also detects union positions (bare prefixes with multiple named types)
// and returns goUnion descriptors for them.
func buildGoTypes(paths []string) ([]goType, []*goUnion) {
	// First pass: collect type intros per bare prefix.
	type prefixInfo struct {
		types []string // type names at this position
		name  string   // field name (e.g., "items")
		index string   // index part (e.g., "[]")
	}
	prefixes := make(map[string]*prefixInfo)
	typeOrder := []string{}
	typeSeen := make(map[string]bool)
	typeFields := make(map[string][]goField)

	for _, path := range paths {
		segs := parsePath(path)
		if len(segs) == 0 {
			continue
		}
		last := segs[len(segs)-1]
		if last.typ == "" {
			continue
		}
		typeName := cleanTypeName(last.typ)
		if isPrimitiveType(typeName) {
			continue
		}
		bare := buildBare(segs)
		pi := prefixes[bare]
		if pi == nil {
			pi = &prefixInfo{name: last.name, index: last.index}
			prefixes[bare] = pi
		}
		// Add type if not already present at this prefix
		found := false
		for _, t := range pi.types {
			if t == typeName {
				found = true
				break
			}
		}
		if !found {
			pi.types = append(pi.types, typeName)
		}
		if !typeSeen[typeName] {
			typeSeen[typeName] = true
			typeOrder = append(typeOrder, typeName)
		}
	}

	// Build prefixToType for parent lookups (first type at each position).
	prefixToType := make(map[string]string)
	for bare, pi := range prefixes {
		prefixToType[bare] = pi.types[0]
	}

	// Identify union positions (>1 named type at the same bare prefix).
	unionsByBare := make(map[string]*goUnion)
	var unions []*goUnion
	for bare, pi := range prefixes {
		if len(pi.types) <= 1 {
			continue
		}
		ifaceName := singularize(snakeToPascal(pi.name))
		if ifaceName == "" {
			ifaceName = "RootItem"
		}
		// Avoid collision with concrete type names
		for _, t := range pi.types {
			if t == ifaceName {
				ifaceName += "Variant"
				break
			}
		}
		u := &goUnion{
			name:          ifaceName,
			concreteTypes: pi.types,
			index:         pi.index,
			fieldName:     pi.name,
			uniqueFields:  make(map[string][]string),
		}
		unionsByBare[bare] = u
		unions = append(unions, u)
	}

	// Second pass: assign fields to their owning types.
	for _, path := range paths {
		segs := parsePath(path)
		if len(segs) == 0 {
			continue
		}
		last := segs[len(segs)-1]
		if last.typ == "" || last.name == "" {
			continue
		}
		typeName := cleanTypeName(last.typ)

		// Find the parent type.
		parentType := ""
		if len(segs) == 1 {
			if pt, ok := prefixToType[""]; ok {
				parentType = pt
			}
		} else {
			for depth := len(segs) - 2; depth >= 0; depth-- {
				// Prefer explicit type annotation on segment (handles multi-type).
				if segs[depth].typ != "" && !isPrimitiveType(cleanTypeName(segs[depth].typ)) {
					parentType = cleanTypeName(segs[depth].typ)
					break
				}
				// Fall back to bare prefix lookup.
				prefix := buildBare(segs[:depth+1])
				if pt, ok := prefixToType[prefix]; ok {
					parentType = pt
					break
				}
			}
		}
		if parentType == "" {
			continue
		}

		// Determine the Go type for this field.
		lastBare := buildBare(segs)
		var goTyp string
		if u, isUnion := unionsByBare[lastBare]; isUnion && !isPrimitiveType(typeName) {
			goTyp = u.wrapperTypeName()
		} else {
			goTyp = flatTypeToGo(typeName, last.index)
		}

		optional := strings.HasSuffix(last.typ, "?")
		if optional {
			goTyp = makePointer(goTyp)
		}

		field := goField{
			goName:   snakeToPascal(last.name),
			jsonName: last.name,
			goType:   goTyp,
			optional: optional,
		}

		// Deduplicate (union fields appear once per concrete type but the
		// parent field should only be added once with the wrapper type).
		existing := typeFields[parentType]
		dup := false
		for _, ef := range existing {
			if ef.jsonName == field.jsonName {
				dup = true
				break
			}
		}
		if !dup {
			typeFields[parentType] = append(existing, field)
		}
	}

	// Compute shared and unique fields for each union.
	for _, u := range unions {
		fieldCounts := make(map[string]int)
		fieldByJSON := make(map[string]goField)

		for _, typeName := range u.concreteTypes {
			for _, f := range typeFields[typeName] {
				fieldCounts[f.jsonName]++
				if _, exists := fieldByJSON[f.jsonName]; !exists {
					fieldByJSON[f.jsonName] = f
				}
			}
		}

		nTypes := len(u.concreteTypes)
		for jsonName, count := range fieldCounts {
			if count == nTypes {
				u.sharedFields = append(u.sharedFields, fieldByJSON[jsonName])
				if jsonName == "type" || jsonName == "kind" || jsonName == "_type" {
					u.typeFieldJSON = jsonName
				}
			}
		}
		sortGoFields(u.sharedFields)

		for _, typeName := range u.concreteTypes {
			typeFieldSet := make(map[string]bool)
			for _, f := range typeFields[typeName] {
				typeFieldSet[f.jsonName] = true
			}
			var unique []string
			for name := range typeFieldSet {
				if fieldCounts[name] == 1 {
					unique = append(unique, name)
				}
			}
			sort.Strings(unique)
			u.uniqueFields[typeName] = unique
		}
	}

	var types []goType
	for _, name := range typeOrder {
		fields := typeFields[name]
		sortGoFields(fields)
		types = append(types, goType{name: name, fields: fields})
	}
	return types, unions
}

// writeUnionCode generates the interface, discriminator, marker methods,
// getters, and wrapper type for a union.
func writeUnionCode(buf *strings.Builder, u *goUnion) {
	marker := u.markerMethod()

	// Interface
	buf.WriteString(fmt.Sprintf("// %s can be one of: %s.\n",
		u.name, strings.Join(u.concreteTypes, ", ")))
	if u.typeFieldJSON != "" {
		buf.WriteString(fmt.Sprintf(
			"// CHANGE ME: the shared %q field is likely a discriminator — see %s below.\n",
			u.typeFieldJSON, u.unmarshalFuncName()))
	}
	buf.WriteString(fmt.Sprintf("type %s interface {\n", u.name))
	buf.WriteString(fmt.Sprintf("\t%s()\n", marker))
	for _, f := range u.sharedFields {
		buf.WriteString(fmt.Sprintf("\tGet%s() %s\n", f.goName, f.goType))
	}
	buf.WriteString("}\n\n")

	// Marker methods
	for _, t := range u.concreteTypes {
		buf.WriteString(fmt.Sprintf("func (*%s) %s() {}\n", t, marker))
	}
	buf.WriteByte('\n')

	// Getter implementations
	if len(u.sharedFields) > 0 {
		for _, t := range u.concreteTypes {
			for _, f := range u.sharedFields {
				buf.WriteString(fmt.Sprintf("func (v *%s) Get%s() %s { return v.%s }\n",
					t, f.goName, f.goType, f.goName))
			}
			buf.WriteByte('\n')
		}
	}

	// Unmarshal function
	writeUnmarshalFunc(buf, u)

	// Wrapper type
	writeWrapperType(buf, u)
}

func writeUnmarshalFunc(buf *strings.Builder, u *goUnion) {
	buf.WriteString(fmt.Sprintf("// %s decodes a JSON value into the matching %s variant.\n",
		u.unmarshalFuncName(), u.name))
	buf.WriteString(fmt.Sprintf("func %s(data json.RawMessage) (%s, error) {\n",
		u.unmarshalFuncName(), u.name))

	// CHANGE ME comment
	if u.typeFieldJSON != "" {
		goFieldName := snakeToPascal(u.typeFieldJSON)
		buf.WriteString(fmt.Sprintf(
			"\t// CHANGE ME: switch on the %q discriminator instead of probing unique keys:\n",
			u.typeFieldJSON))
		buf.WriteString(fmt.Sprintf(
			"\t// var probe struct{ %s string `json:\"%s\"` }\n", goFieldName, u.typeFieldJSON))
		buf.WriteString("\t// if err := json.Unmarshal(data, &probe); err == nil {\n")
		buf.WriteString(fmt.Sprintf("\t//     switch probe.%s {\n", goFieldName))
		for _, t := range u.concreteTypes {
			buf.WriteString(fmt.Sprintf(
				"\t//     case \"???\":\n\t//         var v %s\n\t//         return &v, json.Unmarshal(data, &v)\n", t))
		}
		buf.WriteString("\t//     }\n\t// }\n\n")
	} else {
		buf.WriteString(
			"\t// CHANGE ME: if the variants share a \"type\" or \"kind\" field,\n" +
				"\t// switch on its value instead of probing for unique keys.\n\n")
	}

	buf.WriteString("\tvar keys map[string]json.RawMessage\n")
	buf.WriteString("\tif err := json.Unmarshal(data, &keys); err != nil {\n")
	buf.WriteString("\t\treturn nil, err\n")
	buf.WriteString("\t}\n")

	// Pick fallback type (the one with fewest unique fields).
	fallbackType := u.concreteTypes[0]
	fallbackCount := len(u.uniqueFields[fallbackType])
	for _, t := range u.concreteTypes[1:] {
		if len(u.uniqueFields[t]) < fallbackCount {
			fallbackType = t
			fallbackCount = len(u.uniqueFields[t])
		}
	}

	// Probe unique fields for each non-fallback type.
	for _, t := range u.concreteTypes {
		if t == fallbackType {
			continue
		}
		unique := u.uniqueFields[t]
		if len(unique) == 0 {
			buf.WriteString(fmt.Sprintf(
				"\t// CHANGE ME: %s has no unique fields — add a discriminator.\n", t))
			continue
		}
		buf.WriteString(fmt.Sprintf("\tif _, ok := keys[%q]; ok {\n", unique[0]))
		buf.WriteString(fmt.Sprintf("\t\tvar v %s\n", t))
		buf.WriteString("\t\treturn &v, json.Unmarshal(data, &v)\n")
		buf.WriteString("\t}\n")
	}

	buf.WriteString(fmt.Sprintf("\tvar v %s\n", fallbackType))
	buf.WriteString("\treturn &v, json.Unmarshal(data, &v)\n")
	buf.WriteString("}\n\n")
}

func writeWrapperType(buf *strings.Builder, u *goUnion) {
	wrapper := u.wrapperTypeName()
	unmarshalFunc := u.unmarshalFuncName()

	if u.index == "[]" {
		buf.WriteString(fmt.Sprintf("// %s handles JSON unmarshaling of %s union values.\n",
			wrapper, u.name))
		buf.WriteString(fmt.Sprintf("type %s []%s\n\n", wrapper, u.name))
		buf.WriteString(fmt.Sprintf("func (s *%s) UnmarshalJSON(data []byte) error {\n", wrapper))
		buf.WriteString("\tvar raw []json.RawMessage\n")
		buf.WriteString("\tif err := json.Unmarshal(data, &raw); err != nil {\n")
		buf.WriteString("\t\treturn err\n")
		buf.WriteString("\t}\n")
		buf.WriteString(fmt.Sprintf("\t*s = make(%s, len(raw))\n", wrapper))
		buf.WriteString("\tfor i, msg := range raw {\n")
		buf.WriteString(fmt.Sprintf("\t\tv, err := %s(msg)\n", unmarshalFunc))
		buf.WriteString("\t\tif err != nil {\n")
		buf.WriteString(fmt.Sprintf("\t\t\treturn fmt.Errorf(\"%s[%%d]: %%w\", i, err)\n", u.fieldName))
		buf.WriteString("\t\t}\n")
		buf.WriteString("\t\t(*s)[i] = v\n")
		buf.WriteString("\t}\n")
		buf.WriteString("\treturn nil\n")
		buf.WriteString("}\n")
	} else if strings.HasPrefix(u.index, "[") {
		keyType := u.index[1 : len(u.index)-1]
		buf.WriteString(fmt.Sprintf("// %s handles JSON unmarshaling of %s union values.\n",
			wrapper, u.name))
		buf.WriteString(fmt.Sprintf("type %s map[%s]%s\n\n", wrapper, keyType, u.name))
		buf.WriteString(fmt.Sprintf("func (m *%s) UnmarshalJSON(data []byte) error {\n", wrapper))
		buf.WriteString(fmt.Sprintf("\tvar raw map[%s]json.RawMessage\n", keyType))
		buf.WriteString("\tif err := json.Unmarshal(data, &raw); err != nil {\n")
		buf.WriteString("\t\treturn err\n")
		buf.WriteString("\t}\n")
		buf.WriteString(fmt.Sprintf("\t*m = make(%s, len(raw))\n", wrapper))
		buf.WriteString("\tfor k, msg := range raw {\n")
		buf.WriteString(fmt.Sprintf("\t\tv, err := %s(msg)\n", unmarshalFunc))
		buf.WriteString("\t\tif err != nil {\n")
		buf.WriteString(fmt.Sprintf("\t\t\treturn fmt.Errorf(\"%s[%%v]: %%w\", k, err)\n", u.fieldName))
		buf.WriteString("\t\t}\n")
		buf.WriteString("\t\t(*m)[k] = v\n")
		buf.WriteString("\t}\n")
		buf.WriteString("\treturn nil\n")
		buf.WriteString("}\n")
	}
}

// flatTypeToGo converts a flat path type annotation to a Go type string.
func flatTypeToGo(typ, index string) string {
	base := primitiveToGo(typ)

	if index == "" {
		return base
	}

	// Parse index segments right-to-left to build the type inside-out
	var indices []string
	i := 0
	for i < len(index) {
		if index[i] != '[' {
			break
		}
		end := strings.IndexByte(index[i:], ']')
		if end < 0 {
			break
		}
		indices = append(indices, index[i:i+end+1])
		i = i + end + 1
	}

	result := base
	for j := len(indices) - 1; j >= 0; j-- {
		idx := indices[j]
		switch idx {
		case "[]":
			result = "[]" + result
		case "[int]":
			result = "map[int]" + result
		case "[string]":
			result = "map[string]" + result
		default:
			key := idx[1 : len(idx)-1]
			result = "map[" + key + "]" + result
		}
	}
	return result
}

func primitiveToGo(typ string) string {
	switch typ {
	case "string":
		return "string"
	case "int":
		return "int64"
	case "float":
		return "float64"
	case "bool":
		return "bool"
	case "null", "unknown":
		return "any"
	default:
		return typ
	}
}

func isPrimitiveType(typ string) bool {
	switch typ {
	case "string", "int", "float", "bool", "null", "unknown", "any":
		return true
	}
	return false
}

func makePointer(typ string) string {
	if strings.HasPrefix(typ, "[]") || strings.HasPrefix(typ, "map[") {
		return typ
	}
	return "*" + typ
}

func cleanTypeName(typ string) string {
	return strings.TrimSuffix(typ, "?")
}

func sortGoFields(fields []goField) {
	priority := map[string]int{
		"id": 0, "name": 1, "type": 2, "slug": 3, "label": 4,
	}
	sort.SliceStable(fields, func(i, j int) bool {
		pi, oki := priority[fields[i].jsonName]
		pj, okj := priority[fields[j].jsonName]
		if oki && okj {
			return pi < pj
		}
		if oki {
			return true
		}
		if okj {
			return false
		}
		return fields[i].jsonName < fields[j].jsonName
	})
}
