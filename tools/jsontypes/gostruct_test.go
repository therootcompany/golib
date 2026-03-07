package jsontypes

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestGenerateGoStructsSimple(t *testing.T) {
	paths := []string{
		"{Root}",
		".rooms[]{Room}",
		".rooms[].id{int}",
		".rooms[].name{string}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	if !strings.Contains(got, "Rooms []Room") {
		t.Error("expected Root to have 'Rooms []Room' field")
	}
	if !strings.Contains(got, "type Root struct") {
		t.Error("expected Root struct")
	}
	if !strings.Contains(got, "type Room struct") {
		t.Error("expected Room struct")
	}
}

func TestGenerateGoStructsEmptyContainers(t *testing.T) {
	paths := []string{
		"{Root}",
		".id{int}",
		".metadata{any}",
		".tags[]{any}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	if !strings.Contains(got, "Metadata any") {
		t.Error("expected 'Metadata any' for empty object")
	}
	if !strings.Contains(got, "Tags") || !strings.Contains(got, "[]any") {
		t.Error("expected Tags field with []any type for empty array")
	}
}

func TestGenerateGoStructsOptional(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[].id{int}",
		".items[].email{string?}",
		".items[].meta{Meta?}",
		".items[].meta.score{int}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	if !strings.Contains(got, "Email *string") {
		t.Error("expected '*string' for optional string")
	}
	if !strings.Contains(got, `"email,omitempty"`) {
		t.Error("expected omitempty for optional field")
	}
	if !strings.Contains(got, "*Meta") || !strings.Contains(got, `"meta,omitempty"`) {
		t.Error("expected '*Meta' with omitempty for optional struct")
	}
}

func TestGenerateGoStructsMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".data[string]{Item}",
		".data[string].name{string}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	if !strings.Contains(got, "Data map[string]Item") {
		t.Error("expected 'Data map[string]Item'")
	}
}

// TestGoStructRoundTrip verifies that generated Go structs can unmarshal the
// source JSON and re-marshal it without losing fields. It writes a temporary
// Go program, compiles it, and runs it.
func TestGoStructRoundTrip(t *testing.T) {
	tests := []struct {
		name string
		json string
	}{
		{
			"flat_struct",
			`{"id": 1, "name": "Alice", "active": true, "score": 3.14}`,
		},
		{
			"nested_struct",
			`{"user": {"id": 1, "name": "Bob", "address": {"city": "NYC", "zip": "10001"}}}`,
		},
		{
			"array_of_structs",
			`{"items": [{"id": 1, "name": "a"}, {"id": 2, "name": "b"}]}`,
		},
		{
			"optional_fields",
			`{"items": [{"id": 1, "name": "a", "email": "x@y"}, {"id": 2, "name": "b", "email": null}]}`,
		},
		{
			"empty_containers",
			`{"id": 1, "tags": [], "meta": {}}`,
		},
		{
			"nested_arrays",
			`{"groups": [{"id": 1, "members": [{"id": 10, "role": "admin"}]}]}`,
		},
		{
			"all_primitives",
			`{"s": "hello", "i": 42, "f": 1.5, "b": true, "n": null}`,
		},
		{
			"string_array",
			`{"tags": ["go", "rust", "zig"]}`,
		},
		{
			"root_array",
			`[{"id": 1, "name": "x"}, {"id": 2, "name": "y"}]`,
		},
		{
			"deeply_nested",
			`{"a": {"b": {"c": {"d": "leaf"}}}}`,
		},
		{
			"mixed_optional_struct",
			`{"items": [{"id": 1, "detail": {"score": 5}}, {"id": 2, "detail": null}]}`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			goCode := GenerateGoStructsFromJSON(t, tt.json)
			t.Logf("generated structs:\n%s", goCode)

			// Determine root type — first type declared
			rootType := extractRootType(goCode)
			if rootType == "" {
				t.Fatal("no root type found in generated code")
			}

			isArray := strings.HasPrefix(strings.TrimSpace(tt.json), "[")
			roundTripGoCode := buildRoundTripProgram(goCode, rootType, tt.json, isArray)

			runGoProgram(t, tt.name, roundTripGoCode)
		})
	}
}

// TestGoStructRoundTripProdJSON tests against the production JSON file if available.
func TestGoStructRoundTripProdJSON(t *testing.T) {
	const path = "/tmp/rooms-prod-slow-correct.pretty.json"
	data, err := os.ReadFile(path)
	if err != nil {
		t.Skipf("skipping: %v", err)
	}

	goCode := GenerateGoStructsFromJSON(t, string(data))
	rootType := extractRootType(goCode)
	if rootType == "" {
		t.Fatal("no root type found in generated code")
	}

	roundTripGoCode := buildRoundTripProgram(goCode, rootType, string(data), false)
	runGoProgram(t, "prod_json", roundTripGoCode)
}

// GenerateGoStructsFromJSON runs the full pipeline: parse → analyze → format → generate.
func GenerateGoStructsFromJSON(t *testing.T, jsonStr string) string {
	t.Helper()

	var data any
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		t.Fatalf("parse JSON: %v", err)
	}

	a := testAnalyzer(t)
	rawPaths := a.Analyze(".", data)
	formatted := FormatPaths(rawPaths)
	return GenerateGoStructs(formatted)
}

func extractRootType(goCode string) string {
	for _, line := range strings.Split(goCode, "\n") {
		if strings.HasPrefix(line, "type ") && strings.HasSuffix(line, "struct {") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				return parts[1]
			}
		}
	}
	return ""
}

// buildRoundTripProgram creates a Go main program that:
// 1. Unmarshals the JSON into the generated root type
// 2. Re-marshals it back to JSON
// 3. Unmarshals both original and re-marshaled into map[string]any
// 4. Compares that all original keys are present in the round-tripped version
func buildRoundTripProgram(structs, rootType, jsonData string, isArray bool) string {
	// Escape backticks in JSON by splitting into raw string segments
	jsonLiteral := escapeForGoRawString(jsonData)

	unmarshalTarget := fmt.Sprintf("new(%s)", rootType)
	if isArray {
		unmarshalTarget = fmt.Sprintf("new([]%s)", rootType)
	}

	return fmt.Sprintf(`package main

import (
	"encoding/json"
	"fmt"
	"os"
	"reflect"
)

%s

func main() {
	input := %s

	// Unmarshal into generated struct
	target := %s
	if err := json.Unmarshal([]byte(input), target); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal into struct failed: %%v\n", err)
		os.Exit(1)
	}

	// Re-marshal back to JSON
	out, err := json.Marshal(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "re-marshal failed: %%v\n", err)
		os.Exit(1)
	}

	// Compare: unmarshal both into generic types and check key coverage
	var original, roundTripped any
	if err := json.Unmarshal([]byte(input), &original); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal original: %%v\n", err)
		os.Exit(1)
	}
	if err := json.Unmarshal(out, &roundTripped); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal round-tripped: %%v\n", err)
		os.Exit(1)
	}

	missing := checkKeys("", original, roundTripped)
	if len(missing) > 0 {
		for _, m := range missing {
			fmt.Fprintf(os.Stderr, "MISSING: %%s\n", m)
		}
		os.Exit(1)
	}
	fmt.Println("OK")
}

// checkKeys recursively compares two generic JSON values and returns paths
// where keys from 'a' are missing in 'b'. It ignores value differences
// (types may differ due to int64 vs float64, etc.) — it only checks structure.
func checkKeys(path string, a, b any) []string {
	var missing []string

	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return []string{path + " (expected object, got " + reflect.TypeOf(b).String() + ")"}
		}
		for k, aVal := range av {
			childPath := path + "." + k
			bVal, exists := bv[k]
			if !exists {
				// omitempty can drop null/zero fields — only flag if original was non-null
				if aVal != nil {
					missing = append(missing, childPath)
				}
				continue
			}
			missing = append(missing, checkKeys(childPath, aVal, bVal)...)
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return []string{path + " (expected array, got " + reflect.TypeOf(b).String() + ")"}
		}
		// Check up to min length
		n := len(av)
		if len(bv) < n {
			n = len(bv)
			missing = append(missing, fmt.Sprintf("%%s (array length %%d vs %%d)", path, len(av), len(bv)))
		}
		for i := 0; i < n; i++ {
			missing = append(missing, checkKeys(fmt.Sprintf("%%s[%%d]", path, i), av[i], bv[i])...)
		}
	}
	return missing
}
`, structs, jsonLiteral, unmarshalTarget)
}

// escapeForGoRawString handles JSON that might contain backticks by using
// string concatenation with interpreted string literals for those parts.
func escapeForGoRawString(s string) string {
	if !strings.Contains(s, "`") {
		return "`" + s + "`"
	}
	// Fall back to interpreted string literal with escaping
	b, _ := json.Marshal(s)
	return string(b)
}

func runGoProgram(t *testing.T, name, code string) {
	t.Helper()

	dir := t.TempDir()
	mainFile := filepath.Join(dir, "main.go")
	if err := os.WriteFile(mainFile, []byte(code), 0o644); err != nil {
		t.Fatalf("write temp file: %v", err)
	}

	cmd := exec.Command("go", "run", mainFile)
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("round-trip %s failed:\n%s\n\ngenerated code:\n%s", name, output, code)
	}
	if !strings.Contains(string(output), "OK") {
		t.Fatalf("unexpected output: %s", output)
	}
}

func TestGenerateGoStructsUnion(t *testing.T) {
	// Formatted paths as produced when user chooses "different" types
	paths := []string{
		"{Root}",
		".items[]{FileField}",
		".items[]{FileField}.slug{string}",
		".items[]{FileField}.filename{string}",
		".items[]{FileField}.is_required{bool}",
		".items[]{FeatureField}",
		".items[]{FeatureField}.slug{string}",
		".items[]{FeatureField}.feature{string}",
		".items[]{FeatureField}.archived{bool}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	// Should have the interface
	if !strings.Contains(got, "type Item interface") {
		t.Error("expected Item interface")
	}
	// Marker method
	if !strings.Contains(got, "isItem()") {
		t.Error("expected isItem marker method")
	}
	// Shared field getter (slug is common)
	if !strings.Contains(got, "GetSlug() string") {
		t.Error("expected GetSlug getter in interface")
	}
	// Concrete marker implementations
	if !strings.Contains(got, "func (*FileField) isItem()") {
		t.Error("expected FileField marker implementation")
	}
	if !strings.Contains(got, "func (*FeatureField) isItem()") {
		t.Error("expected FeatureField marker implementation")
	}
	// Unmarshal function
	if !strings.Contains(got, "func unmarshalItem(") {
		t.Error("expected unmarshalItem function")
	}
	// Unique field probes (one type is probed, the other is fallback)
	hasProbe := strings.Contains(got, `keys["filename"]`) ||
		strings.Contains(got, `keys["is_required"]`) ||
		strings.Contains(got, `keys["feature"]`) ||
		strings.Contains(got, `keys["archived"]`)
	if !hasProbe {
		t.Error("expected at least one unique field probe")
	}
	// Wrapper type
	if !strings.Contains(got, "type ItemSlice []Item") {
		t.Error("expected ItemSlice wrapper type")
	}
	if !strings.Contains(got, "func (s *ItemSlice) UnmarshalJSON") {
		t.Error("expected UnmarshalJSON on ItemSlice")
	}
	// Parent field uses wrapper type
	if !strings.Contains(got, "ItemSlice") {
		t.Error("expected Root.Items to use ItemSlice type")
	}
	// Import block
	if !strings.Contains(got, `"encoding/json"`) {
		t.Error("expected encoding/json import")
	}
}

func TestGenerateGoStructsUnionWithTypeField(t *testing.T) {
	// Union where concrete types share a "type" field
	paths := []string{
		"{Root}",
		".events[]{ClickEvent}",
		".events[]{ClickEvent}.type{string}",
		".events[]{ClickEvent}.x{int}",
		".events[]{ClickEvent}.y{int}",
		".events[]{PageView}",
		".events[]{PageView}.type{string}",
		".events[]{PageView}.url{string}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	// Should suggest using "type" as discriminator
	if !strings.Contains(got, "CHANGE ME") {
		t.Error("expected CHANGE ME comment")
	}
	if !strings.Contains(got, `"type"`) && !strings.Contains(got, `type`) {
		t.Error("expected reference to 'type' discriminator field")
	}
}

func TestGoStructUnionRoundTrip(t *testing.T) {
	// Pre-formatted paths representing a union
	paths := []string{
		"{Root}",
		".count{int}",
		".items[]{FileField}",
		".items[]{FileField}.slug{string}",
		".items[]{FileField}.filename{string}",
		".items[]{FileField}.is_required{bool}",
		".items[]{FeatureField}",
		".items[]{FeatureField}.slug{string}",
		".items[]{FeatureField}.feature{string}",
		".items[]{FeatureField}.archived{bool}",
	}
	goCode := GenerateGoStructs(paths)
	t.Logf("generated:\n%s", goCode)

	jsonData := `{
		"count": 4,
		"items": [
			{"slug": "a", "filename": "x.pdf", "is_required": true},
			{"slug": "b", "filename": "y.pdf", "is_required": false},
			{"slug": "c", "feature": "upload", "archived": false},
			{"slug": "d", "feature": "export", "archived": true}
		]
	}`

	program := buildUnionRoundTripProgram(goCode, jsonData)
	runGoProgram(t, "union_round_trip", program)
}

// buildUnionRoundTripProgram creates a Go program that unmarshals JSON through
// the generated union types, checks concrete type dispatch, and re-marshals.
func buildUnionRoundTripProgram(structs, jsonData string) string {
	jsonLiteral := escapeForGoRawString(jsonData)

	// The generated structs already include import block with encoding/json and fmt.
	// Only add os.
	return fmt.Sprintf(`package main

import "os"

%s

func main() {
	input := %s

	var root Root
	if err := json.Unmarshal([]byte(input), &root); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal failed: %%v\n", err)
		os.Exit(1)
	}

	if len(root.Items) != 4 {
		fmt.Fprintf(os.Stderr, "expected 4 items, got %%d\n", len(root.Items))
		os.Exit(1)
	}

	// Check that concrete types were dispatched correctly
	for i, item := range root.Items {
		switch v := item.(type) {
		case *FileField:
			if i >= 2 {
				fmt.Fprintf(os.Stderr, "item[%%d]: expected FeatureField, got FileField\n", i)
				os.Exit(1)
			}
			if v.Filename == "" {
				fmt.Fprintf(os.Stderr, "item[%%d]: FileField.Filename is empty\n", i)
				os.Exit(1)
			}
		case *FeatureField:
			if i < 2 {
				fmt.Fprintf(os.Stderr, "item[%%d]: expected FileField, got FeatureField\n", i)
				os.Exit(1)
			}
			if v.Feature == "" {
				fmt.Fprintf(os.Stderr, "item[%%d]: FeatureField.Feature is empty\n", i)
				os.Exit(1)
			}
		default:
			fmt.Fprintf(os.Stderr, "item[%%d]: unexpected type %%T\n", i, item)
			os.Exit(1)
		}

		// Test shared field getter
		if item.GetSlug() == "" {
			fmt.Fprintf(os.Stderr, "item[%%d]: GetSlug() returned empty\n", i)
			os.Exit(1)
		}
	}

	// Re-marshal and verify
	out, err := json.Marshal(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "re-marshal failed: %%v\n", err)
		os.Exit(1)
	}

	// Verify round-trip preserves structure
	var check Root
	if err := json.Unmarshal(out, &check); err != nil {
		fmt.Fprintf(os.Stderr, "re-unmarshal failed: %%v\n", err)
		os.Exit(1)
	}
	if len(check.Items) != 4 {
		fmt.Fprintf(os.Stderr, "round-trip: expected 4 items, got %%d\n", len(check.Items))
		os.Exit(1)
	}

	fmt.Println("OK")
}
`, structs, jsonLiteral)
}

// --- Union: 3+ types ---

func TestGenerateGoStructsUnionThreeTypes(t *testing.T) {
	paths := []string{
		"{Root}",
		".events[]{ClickEvent}",
		".events[]{ClickEvent}.action{string}",
		".events[]{ClickEvent}.x{int}",
		".events[]{PageView}",
		".events[]{PageView}.action{string}",
		".events[]{PageView}.url{string}",
		".events[]{ErrorEvent}",
		".events[]{ErrorEvent}.action{string}",
		".events[]{ErrorEvent}.code{int}",
		".events[]{ErrorEvent}.message{string}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	if !strings.Contains(got, "type Event interface") {
		t.Error("expected Event interface")
	}
	for _, typ := range []string{"ClickEvent", "PageView", "ErrorEvent"} {
		if !strings.Contains(got, "func (*"+typ+") isEvent()") {
			t.Errorf("expected %s marker implementation", typ)
		}
	}
	// Shared field getter
	if !strings.Contains(got, "GetAction() string") {
		t.Error("expected GetAction getter for shared 'action' field")
	}
	// Should have probes for at least 2 of the 3 types (one is fallback)
	probes := 0
	for _, key := range []string{`keys["x"]`, `keys["url"]`, `keys["code"]`, `keys["message"]`} {
		if strings.Contains(got, key) {
			probes++
		}
	}
	if probes < 2 {
		t.Errorf("expected at least 2 unique field probes, found %d", probes)
	}
}

// --- Union: name collision with concrete type ---

func TestGenerateGoStructsUnionNameCollision(t *testing.T) {
	// Field "items" singularizes to "Item", which collides with concrete type "Item".
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[]{Item}.id{int}",
		".items[]{Item}.path{string}",
		".items[]{Other}",
		".items[]{Other}.id{int}",
		".items[]{Other}.score{float}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	// Interface should NOT be named "Item" since that's a concrete type.
	// Should use "ItemVariant" or similar.
	if strings.Contains(got, "type Item interface") {
		t.Error("interface should not be named 'Item' — collides with concrete type")
	}
	if !strings.Contains(got, "Variant") {
		t.Error("expected 'Variant' suffix to avoid name collision")
	}
}

// --- Union: map-based ---

func TestGenerateGoStructsUnionMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".data[string]{TypeA}",
		".data[string]{TypeA}.name{string}",
		".data[string]{TypeA}.path{string}",
		".data[string]{TypeB}",
		".data[string]{TypeB}.name{string}",
		".data[string]{TypeB}.score{float}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	if !strings.Contains(got, "Map") {
		t.Error("expected map wrapper type")
	}
	if !strings.Contains(got, "map[string]json.RawMessage") {
		t.Error("expected map[string]json.RawMessage in UnmarshalJSON")
	}
}

// --- Union: end-to-end through analyzer ---

func TestGoStructUnionEndToEnd(t *testing.T) {
	arr := []any{
		map[string]any{"slug": "a", "filename": "x.pdf", "is_required": true},
		map[string]any{"slug": "b", "filename": "y.pdf", "is_required": false},
		map[string]any{"slug": "c", "feature": "upload", "archived": false},
		map[string]any{"slug": "d", "feature": "export", "archived": true},
	}
	obj := map[string]any{"items": arr, "count": jsonNum("4"), "status": "ok"}

	a := &Analyzer{
		Prompter: &Prompter{
			reader:       bufio.NewReader(strings.NewReader("")),
			output:       io.Discard,
			priorAnswers: []string{"d", "FileField", "FeatureField"},
		},
		knownTypes:  make(map[string]*structType),
		typesByName: make(map[string]*structType),
	}
	rawPaths := a.Analyze(".", obj)
	formatted := FormatPaths(rawPaths)
	goCode := GenerateGoStructs(formatted)
	t.Logf("formatted paths:\n  %s", strings.Join(formatted, "\n  "))
	t.Logf("generated Go:\n%s", goCode)

	if !strings.Contains(goCode, "interface") {
		t.Error("expected union interface from end-to-end")
	}
	if !strings.Contains(goCode, "Slice") {
		t.Error("expected wrapper slice type")
	}
	// The analyzer assigns type names to shapes in encounter order.
	// Verify both user-provided names appear (may be swapped vs our expectation).
	if !strings.Contains(goCode, "FileField") || !strings.Contains(goCode, "FeatureField") {
		t.Errorf("expected both FileField and FeatureField in output")
	}
	if !strings.Contains(goCode, "unmarshal") {
		t.Error("expected unmarshal function")
	}
}

// --- Union: round-trip with type discriminator wired up ---

func TestGoStructUnionRoundTripWithDiscriminator(t *testing.T) {
	// Manually craft Go code that uses a "type" discriminator switch
	// to prove the pattern works when the user uncomments the CHANGE ME code.
	goCode := `
import (
	"encoding/json"
	"fmt"
)

type Root struct {
	Events EventSlice ` + "`json:\"events\"`" + `
}

type ClickEvent struct {
	Type string ` + "`json:\"type\"`" + `
	X    int64  ` + "`json:\"x\"`" + `
	Y    int64  ` + "`json:\"y\"`" + `
}

type PageView struct {
	Type string ` + "`json:\"type\"`" + `
	Url  string ` + "`json:\"url\"`" + `
}

type Event interface {
	isEvent()
	GetType() string
}

func (*ClickEvent) isEvent() {}
func (*PageView) isEvent()   {}

func (v *ClickEvent) GetType() string { return v.Type }
func (v *PageView) GetType() string   { return v.Type }

func unmarshalEvent(data json.RawMessage) (Event, error) {
	var probe struct{ Type string ` + "`json:\"type\"`" + ` }
	if err := json.Unmarshal(data, &probe); err != nil {
		return nil, err
	}
	switch probe.Type {
	case "click":
		var v ClickEvent
		return &v, json.Unmarshal(data, &v)
	case "pageview":
		var v PageView
		return &v, json.Unmarshal(data, &v)
	default:
		return nil, fmt.Errorf("unknown event type: %s", probe.Type)
	}
}

type EventSlice []Event

func (s *EventSlice) UnmarshalJSON(data []byte) error {
	var raw []json.RawMessage
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	*s = make(EventSlice, len(raw))
	for i, msg := range raw {
		v, err := unmarshalEvent(msg)
		if err != nil {
			return fmt.Errorf("events[%d]: %w", i, err)
		}
		(*s)[i] = v
	}
	return nil
}
`
	jsonData := `{
		"events": [
			{"type": "click", "x": 10, "y": 20},
			{"type": "pageview", "url": "https://example.com"},
			{"type": "click", "x": 30, "y": 40}
		]
	}`
	jsonLiteral := escapeForGoRawString(jsonData)

	program := fmt.Sprintf(`package main

import "os"

%s

func main() {
	input := %s

	var root Root
	if err := json.Unmarshal([]byte(input), &root); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal failed: %%v\n", err)
		os.Exit(1)
	}
	if len(root.Events) != 3 {
		fmt.Fprintf(os.Stderr, "expected 3 events, got %%d\n", len(root.Events))
		os.Exit(1)
	}
	// Verify dispatch
	if _, ok := root.Events[0].(*ClickEvent); !ok {
		fmt.Fprintf(os.Stderr, "events[0]: expected *ClickEvent, got %%T\n", root.Events[0])
		os.Exit(1)
	}
	if _, ok := root.Events[1].(*PageView); !ok {
		fmt.Fprintf(os.Stderr, "events[1]: expected *PageView, got %%T\n", root.Events[1])
		os.Exit(1)
	}
	// Verify getter
	if root.Events[0].GetType() != "click" {
		fmt.Fprintf(os.Stderr, "events[0].GetType() = %%q, want %%q\n", root.Events[0].GetType(), "click")
		os.Exit(1)
	}
	// Re-marshal round trip
	out, err := json.Marshal(root)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %%v\n", err)
		os.Exit(1)
	}
	var check Root
	if err := json.Unmarshal(out, &check); err != nil {
		fmt.Fprintf(os.Stderr, "re-unmarshal: %%v\n", err)
		os.Exit(1)
	}
	if len(check.Events) != 3 {
		fmt.Fprintf(os.Stderr, "round-trip: expected 3 events, got %%d\n", len(check.Events))
		os.Exit(1)
	}
	fmt.Println("OK")
}
`, goCode, jsonLiteral)

	runGoProgram(t, "discriminator_round_trip", program)
}

// --- Mixed int/float same field ---

func TestGoStructRoundTripMixedIntFloat(t *testing.T) {
	// When a field is int in one element and float in another, the analyzer
	// should pick a type that handles both.
	jsonStr := `{"items": [{"id": 1, "score": 10}, {"id": 2, "score": 1.5}]}`
	goCode := GenerateGoStructsFromJSON(t, jsonStr)
	t.Logf("generated:\n%s", goCode)

	// The field should be float64 (not int64) since mixed int/float → float
	if !strings.Contains(goCode, "float64") {
		t.Error("expected float64 for mixed int/float field")
	}

	rootType := extractRootType(goCode)
	program := buildRoundTripProgram(goCode, rootType, jsonStr, false)
	runGoProgram(t, "mixed_int_float", program)
}

// --- Round-trip with maps ---

func TestGoStructRoundTripMap(t *testing.T) {
	jsonStr := `{"data": {"abc123": {"name": "foo", "active": true}, "def456": {"name": "bar", "active": false}, "ghi789": {"name": "baz", "active": true}, "jkl012": {"name": "qux", "active": false}}}`
	goCode := GenerateGoStructsFromJSON(t, jsonStr)
	t.Logf("generated:\n%s", goCode)

	if !strings.Contains(goCode, "map[string]") {
		t.Error("expected map[string] type for data field")
	}

	rootType := extractRootType(goCode)
	program := buildRoundTripProgram(goCode, rootType, jsonStr, false)
	runGoProgram(t, "map_struct", program)
}

// --- Nullable struct inside union ---

func TestGoStructUnionWithNullableNestedStruct(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{TypeA}",
		".items[]{TypeA}.id{int}",
		".items[]{TypeA}.detail{Detail?}",
		".items[]{TypeA}.detail.score{int}",
		".items[]{TypeA}.path{string}",
		".items[]{TypeB}",
		".items[]{TypeB}.id{int}",
		".items[]{TypeB}.label{string}",
	}
	got := GenerateGoStructs(paths)
	t.Logf("output:\n%s", got)

	if !strings.Contains(got, "*Detail") {
		t.Error("expected *Detail for nullable nested struct in union variant")
	}
	if !strings.Contains(got, "type Item interface") {
		t.Error("expected Item interface")
	}
	if !strings.Contains(got, "type Detail struct") {
		t.Error("expected Detail struct definition")
	}
}

// --- Single shape should NOT produce union ---

func TestGoStructSingleShapeNoUnion(t *testing.T) {
	jsonStr := `{"items": [{"slug": "a", "path": "x"}, {"slug": "b", "path": "y"}]}`
	goCode := GenerateGoStructsFromJSON(t, jsonStr)
	t.Logf("generated:\n%s", goCode)

	if strings.Contains(goCode, "interface") {
		t.Error("single shape should not produce a union interface")
	}
	if strings.Contains(goCode, "Slice") {
		t.Error("single shape should not produce a wrapper slice type")
	}
	if strings.Contains(goCode, "encoding/json") {
		t.Error("single shape should not need encoding/json import")
	}
}

// --- Re-marshal value fidelity (not just key presence) ---

func TestGoStructRoundTripValueFidelity(t *testing.T) {
	jsonStr := `{"name": "test", "count": 42, "ratio": 3.14, "active": true, "tags": ["a", "b"], "nested": {"x": 1}}`
	goCode := GenerateGoStructsFromJSON(t, jsonStr)

	rootType := extractRootType(goCode)
	jsonLiteral := escapeForGoRawString(jsonStr)

	// This program checks EXACT value equality, not just key presence.
	program := fmt.Sprintf(`package main

import (
	"encoding/json"
	"fmt"
	"os"
	"math"
)

%s

func main() {
	input := %s

	target := new(%s)
	if err := json.Unmarshal([]byte(input), target); err != nil {
		fmt.Fprintf(os.Stderr, "unmarshal: %%v\n", err)
		os.Exit(1)
	}

	out, err := json.Marshal(target)
	if err != nil {
		fmt.Fprintf(os.Stderr, "marshal: %%v\n", err)
		os.Exit(1)
	}

	// Unmarshal both into generic maps and compare values
	var orig, rt map[string]any
	json.Unmarshal([]byte(input), &orig)
	json.Unmarshal(out, &rt)

	errs := compareValues("", orig, rt)
	if len(errs) > 0 {
		for _, e := range errs {
			fmt.Fprintln(os.Stderr, e)
		}
		os.Exit(1)
	}
	fmt.Println("OK")
}

func compareValues(path string, a, b any) []string {
	var errs []string
	switch av := a.(type) {
	case map[string]any:
		bv, ok := b.(map[string]any)
		if !ok {
			return []string{fmt.Sprintf("%%s: type mismatch: %%T vs %%T", path, a, b)}
		}
		for k := range av {
			errs = append(errs, compareValues(path+"."+k, av[k], bv[k])...)
		}
	case []any:
		bv, ok := b.([]any)
		if !ok {
			return []string{fmt.Sprintf("%%s: type mismatch: %%T vs %%T", path, a, b)}
		}
		if len(av) != len(bv) {
			return []string{fmt.Sprintf("%%s: length %%d vs %%d", path, len(av), len(bv))}
		}
		for i := range av {
			errs = append(errs, compareValues(fmt.Sprintf("%%s[%%d]", path, i), av[i], bv[i])...)
		}
	case float64:
		bv, ok := b.(float64)
		if !ok {
			return []string{fmt.Sprintf("%%s: type mismatch: %%T vs %%T", path, a, b)}
		}
		if math.Abs(av-bv) > 1e-9 {
			return []string{fmt.Sprintf("%%s: value %%v vs %%v", path, av, bv)}
		}
	case string:
		bv, ok := b.(string)
		if !ok || av != bv {
			return []string{fmt.Sprintf("%%s: value %%v vs %%v", path, a, b)}
		}
	case bool:
		bv, ok := b.(bool)
		if !ok || av != bv {
			return []string{fmt.Sprintf("%%s: value %%v vs %%v", path, a, b)}
		}
	case nil:
		if b != nil {
			return []string{fmt.Sprintf("%%s: value nil vs %%v", path, b)}
		}
	}
	return errs
}
`, goCode, jsonLiteral, rootType)

	runGoProgram(t, "value_fidelity", program)
}

// --- Full pipeline anonymous mode with diverse JSON ---

func TestGoStructRoundTripDiverseAnonymous(t *testing.T) {
	jsonStr := `{
		"id": 1,
		"name": "test",
		"settings": {"theme": "dark", "lang": "en", "notify": true},
		"tags": ["go", "rust"],
		"scores": [10, 20, 30],
		"metadata": {},
		"empty_list": [],
		"users": [
			{
				"id": 100,
				"name": "Alice",
				"email": "a@b.com",
				"address": {"city": "NYC", "zip": "10001"},
				"roles": [{"id": 1, "perm": "admin"}]
			},
			{
				"id": 200,
				"name": "Bob",
				"email": null,
				"address": {"city": "LA", "zip": "90001"},
				"roles": []
			}
		],
		"active": true,
		"ratio": 0.75
	}`

	goCode := GenerateGoStructsFromJSON(t, jsonStr)
	t.Logf("generated:\n%s", goCode)

	rootType := extractRootType(goCode)
	program := buildRoundTripProgram(goCode, rootType, jsonStr, false)
	runGoProgram(t, "diverse_anonymous", program)
}

func TestGenerateGoStructsParsePath(t *testing.T) {
	// Verify parsePath handles the formatted output format.
	// Note: formatted paths like ".rooms[]{Room}" parse differently from
	// raw paths like ".{Root}.rooms[]{Room}" — no empty root segment.
	tests := []struct {
		path string
		want []segment
	}{
		{
			"{Root}",
			[]segment{{name: "", typ: "Root"}},
		},
		{
			".rooms[]{Room}",
			[]segment{{name: "rooms", index: "[]", typ: "Room"}},
		},
		{
			".rooms[].id{int}",
			[]segment{{name: "rooms", index: "[]"}, {name: "id", typ: "int"}},
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := parsePath(tt.path)
			if len(got) != len(tt.want) {
				t.Fatalf("got %d segments, want %d: %+v", len(got), len(tt.want), got)
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("segment[%d]: got %+v, want %+v", i, got[i], tt.want[i])
				}
			}
		})
	}
}
