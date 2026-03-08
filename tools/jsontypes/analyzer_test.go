package jsontypes

import (
	"encoding/json"
	"sort"
	"strings"
	"testing"
)

// testAnalyzer creates an analyzer in autonomous mode (no resolver).
func testAnalyzer(t *testing.T) *Analyzer {
	t.Helper()
	return New(AnalyzerConfig{})
}

// scriptedResolver creates a Resolver that returns responses in order.
// After all responses are consumed, it accepts defaults.
func scriptedResolver(responses ...Response) Resolver {
	i := 0
	return func(d *Decision) error {
		if i >= len(responses) {
			d.Response = d.Default
			return nil
		}
		d.Response = responses[i]
		i++
		return nil
	}
}

// testInteractiveAnalyzer creates an analyzer with scripted responses.
func testInteractiveAnalyzer(t *testing.T, responses ...Response) *Analyzer {
	t.Helper()
	return New(AnalyzerConfig{
		Resolver: scriptedResolver(responses...),
	})
}

func sortPaths(paths []string) []string {
	sorted := make([]string, len(paths))
	copy(sorted, paths)
	sort.Strings(sorted)
	return sorted
}

func TestAnalyzePrimitive(t *testing.T) {
	a := testAnalyzer(t)
	tests := []struct {
		name string
		want string
	}{
		{"null", ".{null}"},
		{"bool", ".{bool}"},
		{"int", ".{int}"},
		{"float", ".{float}"},
		{"string", ".{string}"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var val any
			switch tt.name {
			case "null":
				val = nil
			case "bool":
				val = true
			case "int":
				val = jsonNum("42")
			case "float":
				val = jsonNum("3.14")
			case "string":
				val = "hello"
			}
			paths := a.Analyze(".", val)
			if len(paths) != 1 || paths[0] != tt.want {
				t.Errorf("got %v, want [%s]", paths, tt.want)
			}
		})
	}
}

func TestAnalyzeSimpleStruct(t *testing.T) {
	a := testAnalyzer(t)
	obj := map[string]any{
		"name": "Alice",
		"age":  jsonNum("30"),
	}
	paths := sortPaths(a.Analyze(".", obj))
	want := sortPaths([]string{
		".{Root}.age{int}",
		".{Root}.name{string}",
	})
	assertPaths(t, paths, want)
}

func TestAnalyzeMapDetection(t *testing.T) {
	a := testAnalyzer(t)
	// Keys with digits + same length → detected as map
	obj := map[string]any{
		"abc123": map[string]any{"name": "a"},
		"def456": map[string]any{"name": "b"},
		"ghi789": map[string]any{"name": "c"},
	}
	paths := sortPaths(a.Analyze(".", obj))
	want := sortPaths([]string{
		".[string]{RootItem}.name{string}",
	})
	assertPaths(t, paths, want)
}

func TestAnalyzeArrayOfObjects(t *testing.T) {
	a := testAnalyzer(t)
	arr := []any{
		map[string]any{"x": jsonNum("1")},
		map[string]any{"x": jsonNum("2")},
	}
	paths := sortPaths(a.Analyze(".", arr))
	want := sortPaths([]string{
		".[]{RootItem}.x{int}",
	})
	assertPaths(t, paths, want)
}

func TestAnalyzeOptionalFields(t *testing.T) {
	a := testAnalyzer(t)
	// Two objects with different fields → same type with optional fields
	values := []any{
		map[string]any{"name": "Alice", "age": jsonNum("30")},
		map[string]any{"name": "Bob"},
	}
	paths := sortPaths(a.analyzeCollectionValues(".[]", values))
	want := sortPaths([]string{
		".[]{RootItem}.age{null}",
		".[]{RootItem}.age{int}",
		".[]{RootItem}.name{string}",
	})
	assertPaths(t, paths, want)
}

func TestAnalyzeNullableField(t *testing.T) {
	a := testAnalyzer(t)
	values := []any{
		map[string]any{"data": nil},
		map[string]any{"data": "hello"},
	}
	paths := sortPaths(a.analyzeCollectionValues(".[]", values))
	want := sortPaths([]string{
		".[]{RootItem}.data{null}",
		".[]{RootItem}.data{string}",
	})
	assertPaths(t, paths, want)
}

func TestAnalyzeEmptyArray(t *testing.T) {
	a := testAnalyzer(t)
	paths := a.Analyze(".", []any{})
	want := []string{".[]{any}"}
	assertPaths(t, paths, want)
}

func TestAnalyzeEmptyObject(t *testing.T) {
	a := testAnalyzer(t)
	paths := a.Analyze(".", map[string]any{})
	want := []string{".{any}"}
	assertPaths(t, paths, want)
}

func TestHeuristicsMapDetection(t *testing.T) {
	tests := []struct {
		name      string
		keys      []string
		wantMap   bool
		wantConf  bool
	}{
		{"numeric keys", []string{"1", "2", "3"}, true, true},
		{"alphanum IDs", []string{"abc123", "def456", "ghi789"}, true, true},
		{"field names", []string{"name", "age", "email"}, false, true},
		{"two keys", []string{"ab", "cd"}, false, false},
		{"hex IDs", []string{"a1b2c3d4", "e5f6a7b8", "c9d0e1f2"}, true, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			obj := make(map[string]any)
			for _, k := range tt.keys {
				obj[k] = "value"
			}
			isMap, confident := looksLikeMap(obj)
			if isMap != tt.wantMap || confident != tt.wantConf {
				t.Errorf("looksLikeMap(%v) = (%v, %v), want (%v, %v)",
					tt.keys, isMap, confident, tt.wantMap, tt.wantConf)
			}
		})
	}
}

func TestInferTypeName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{".[person_id]", "Person"},
		{".{Root}.friends[]", "Friend"},
		{".{Root}.address", "Address"},
		{".", "Root"},
		{".[]", "RootItem"},
		{".[string]", "RootItem"},
		{".[int]", "RootItem"},
		{".{Root}.json", "RootJSON"},
		{".{Root}.data", "RootData"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := inferTypeName(tt.path)
			if got != tt.want {
				t.Errorf("inferTypeName(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSingularize(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"Friends", "Friend"},
		{"Categories", "Category"},
		{"Boxes", "Box"},
		{"Address", "Address"},
		{"Bus", "Bus"},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			got := singularize(tt.in)
			if got != tt.want {
				t.Errorf("singularize(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

func TestTypeNameSubsetExtends(t *testing.T) {
	// When two objects at the SAME path have overlapping fields (one a subset),
	// they should get the same type name (via name collision + subset merge).
	// Objects at DIFFERENT paths get separate types even if fields overlap,
	// because they represent different domain concepts.
	a := testAnalyzer(t)
	arr := []any{
		map[string]any{"name": "Alice", "age": jsonNum("30")},
		map[string]any{"name": "Bob", "age": jsonNum("25"), "email": "bob@example.com"},
	}
	obj := map[string]any{"people": arr}
	paths := sortPaths(a.Analyze(".", obj))

	// Both array elements should be unified under the same type
	typeName := ""
	for _, p := range paths {
		if strings.Contains(p, ".people[]") {
			if idx := strings.Index(p, "{"); idx >= 0 {
				end := strings.Index(p[idx:], "}")
				if typeName == "" {
					typeName = p[idx+1 : idx+end]
				} else if p[idx+1:idx+end] != typeName && p[idx+1:idx+end] != "Root" {
					t.Errorf("expected all people paths to use type %q, got %s", typeName, p)
				}
			}
		}
	}
	if typeName == "" {
		t.Fatal("expected a type name for people array elements")
	}
}

func TestParentTypeName(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{".[id]{Document}.rooms[]{Room}.details", "Room"},
		{".[id]{Document}.name", "Document"},
		{".items[]", ""},
		{".{Root}.data{null}", "Root"},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := parentTypeName(tt.path)
			if got != tt.want {
				t.Errorf("parentTypeName(%q) = %q, want %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestShortPath(t *testing.T) {
	tests := []struct {
		path string
		want string
	}{
		{
			".{RoomsResult}.rooms[]{Room}.room[string][]{RoomRoom}.json{RoomRoomJSON}.feature_types[]",
			".rooms[].room[string][].json{RoomRoomJSON}.feature_types[]",
		},
		{
			".{Root}.name{string}",
			".name{string}",
		},
		{
			".",
			".",
		},
		{
			".{Root}",
			".{Root}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := shortPath(tt.path)
			if got != tt.want {
				t.Errorf("shortPath(%q)\n  got:  %q\n  want: %q", tt.path, got, tt.want)
			}
		})
	}
}

func TestSuggestAlternativeNameUsesParent(t *testing.T) {
	a := testAnalyzer(t)
	// Register a type named "Room"
	a.registerType("a,b", "Room", map[string]string{"a": "string", "b": "string"})

	// Suggest alternative at a path under {Document}
	got := a.suggestAlternativeName(".[id]{Document}.rooms[]", "Room")
	if got != "DocumentRoom" {
		t.Errorf("got %q, want %q", got, "DocumentRoom")
	}

	// Register DocumentRoom too, then it should fall back to numbered
	a.registerType("c,d", "DocumentRoom", map[string]string{"c": "string", "d": "string"})
	got = a.suggestAlternativeName(".[id]{Document}.rooms[]", "Room")
	if !strings.HasPrefix(got, "Room") || got == "Room" || got == "DocumentRoom" {
		t.Errorf("expected numbered fallback, got %q", got)
	}
}

func TestAutoResolveCollision(t *testing.T) {
	a := testAnalyzer(t)
	// Register a type named "Room" with fields {a, b}
	a.registerType("a,b", "Room", map[string]string{"a": "string", "b": "string"})

	// Analyze an object at a path under {Document} that would infer "Room"
	// but has completely different fields — should auto-resolve to "DocumentRoom"
	obj := map[string]any{"x": "1", "y": "2"}
	paths := a.Analyze(".{Document}.room", obj)

	hasDocumentRoom := false
	for _, p := range paths {
		if strings.Contains(p, "{DocumentRoom}") {
			hasDocumentRoom = true
			break
		}
	}
	if !hasDocumentRoom {
		t.Errorf("expected DocumentRoom type, got:\n  %s", strings.Join(paths, "\n  "))
	}
}

func TestPooledMapDetection(t *testing.T) {
	// Multiple objects each with 1-2 numeric keys should be detected as maps
	// even though individually they have too few keys for heuristics.
	a := testAnalyzer(t)
	values := []any{
		map[string]any{"230108": "a"},
		map[string]any{"138666": "b"},
		map[string]any{"162359": "c"},
		map[string]any{},
	}
	paths := sortPaths(a.analyzeCollectionValues(".data", values))
	// Should detect as maps with numeric keys → [int] (map index, not array)
	hasMapPath := false
	for _, p := range paths {
		if strings.Contains(p, "[int]") || strings.Contains(p, "[string]") {
			hasMapPath = true
			break
		}
	}
	if !hasMapPath {
		t.Errorf("expected map detection (paths with [int] or [string]), got:\n  %s",
			strings.Join(paths, "\n  "))
	}
}

func TestAnalyzeFullSample(t *testing.T) {
	a := testAnalyzer(t)

	data := map[string]any{
		"abc123": map[string]any{
			"name":   "Alice",
			"age":    jsonNum("30"),
			"active": true,
			"friends": []any{
				map[string]any{"name": "Bob", "identification": nil},
				map[string]any{"name": "Charlie", "identification": map[string]any{
					"type": "StateID", "number": "12345", "name": "Charlie C",
				}},
			},
		},
		"def456": map[string]any{
			"name": "Dave", "age": jsonNum("25"), "active": false, "friends": []any{},
		},
		"ghi789": map[string]any{
			"name": "Eve", "age": jsonNum("28"), "active": true, "score": jsonNum("95.5"),
			"friends": []any{
				map[string]any{"name": "Frank", "identification": map[string]any{
					"type": "DriverLicense", "id": "DL-999", "name": "Frank F",
					"restrictions": []any{"corrective lenses"},
				}},
			},
		},
	}

	paths := sortPaths(a.Analyze(".", data))
	want := sortPaths([]string{
		".[string]{RootItem}.active{bool}",
		".[string]{RootItem}.age{int}",
		".[string]{RootItem}.friends[]{Friend}.identification{null}",
		".[string]{RootItem}.friends[]{Friend}.identification{Identification}.id{null}",
		".[string]{RootItem}.friends[]{Friend}.identification{Identification}.id{string}",
		".[string]{RootItem}.friends[]{Friend}.identification{Identification}.name{string}",
		".[string]{RootItem}.friends[]{Friend}.identification{Identification}.number{null}",
		".[string]{RootItem}.friends[]{Friend}.identification{Identification}.number{string}",
		".[string]{RootItem}.friends[]{Friend}.identification{Identification}.restrictions{null}",
		".[string]{RootItem}.friends[]{Friend}.identification{Identification}.restrictions[]{string}",
		".[string]{RootItem}.friends[]{Friend}.identification{Identification}.type{string}",
		".[string]{RootItem}.friends[]{Friend}.name{string}",
		".[string]{RootItem}.name{string}",
		".[string]{RootItem}.score{null}",
		".[string]{RootItem}.score{float}",
	})
	assertPaths(t, paths, want)
}

// TestDifferentTypesViaResolver verifies that when the resolver returns
// IsNewType=true for multiple shapes at the same path:
// 1. Shape names are requested via DecideShapeName
// 2. The named types appear in the final output
func TestDifferentTypesViaResolver(t *testing.T) {
	a := New(AnalyzerConfig{
		Resolver: scriptedResolver(
			Response{IsNewType: true},       // different types for shapes
			Response{Name: "FileField"},     // name for shape 1
			Response{Name: "FeatureField"},  // name for shape 2
		),
	})

	arr := []any{
		// Shape 1: has "filename" and "is_required"
		map[string]any{"slug": "a", "filename": "x.pdf", "is_required": true,
			"meta": map[string]any{"size": jsonNum("100")}},
		map[string]any{"slug": "b", "filename": "y.pdf", "is_required": false,
			"meta": map[string]any{"size": jsonNum("200")}},
		// Shape 2: has "feature" and "archived"
		map[string]any{"slug": "c", "feature": "upload", "archived": false,
			"meta": map[string]any{"version": jsonNum("1")}},
		map[string]any{"slug": "d", "feature": "export", "archived": true,
			"meta": map[string]any{"version": jsonNum("2")}},
	}

	paths := sortPaths(a.Analyze(".{Room}.items[]", arr))

	hasFileField := false
	hasFeatureField := false
	for _, p := range paths {
		if strings.Contains(p, "{FileField}") {
			hasFileField = true
		}
		if strings.Contains(p, "{FeatureField}") {
			hasFeatureField = true
		}
	}
	if !hasFileField {
		t.Errorf("expected {FileField} type in paths:\n  %s", strings.Join(paths, "\n  "))
	}
	if !hasFeatureField {
		t.Errorf("expected {FeatureField} type in paths:\n  %s", strings.Join(paths, "\n  "))
	}

	// Verify the formatted output includes these types
	formatted := FormatPaths(paths)
	foundFileField := false
	foundFeatureField := false
	for _, line := range formatted {
		if strings.Contains(line, "{FileField}") {
			foundFileField = true
		}
		if strings.Contains(line, "{FeatureField}") {
			foundFeatureField = true
		}
	}
	if !foundFileField {
		t.Errorf("formatted output missing {FileField}:\n  %s", strings.Join(formatted, "\n  "))
	}
	if !foundFeatureField {
		t.Errorf("formatted output missing {FeatureField}:\n  %s", strings.Join(formatted, "\n  "))
	}
}

// TestDecideMapOrStructDefault verifies that the library sends
// the inferred type name as the default in DecideMapOrStruct decisions.
func TestDecideMapOrStructDefault(t *testing.T) {
	var captured *Decision
	a := New(AnalyzerConfig{
		Resolver: func(d *Decision) error {
			if d.Kind == DecideMapOrStruct && captured == nil {
				cp := *d
				captured = &cp
			}
			d.Response = d.Default
			return nil
		},
	})

	obj := map[string]any{
		"errors": []any{},
		"rooms":  []any{map[string]any{"name": "foo"}},
	}
	a.Analyze(".", obj)

	if captured == nil {
		t.Fatal("expected DecideMapOrStruct decision")
	}
	if captured.Default.Name != "Root" {
		t.Errorf("expected default name %q, got %q", "Root", captured.Default.Name)
	}
}

// TestDefaultDifferentWhenUniqueFieldsDominate verifies that when shapes share
// only ubiquitous fields (slug, name, etc.) and have many unique fields, the
// default response suggests different types (IsNewType=true).
func TestDefaultDifferentWhenUniqueFieldsDominate(t *testing.T) {
	var unifyDecision *Decision
	a := New(AnalyzerConfig{
		Resolver: func(d *Decision) error {
			if d.Kind == DecideUnifyShapes && unifyDecision == nil {
				cp := *d
				unifyDecision = &cp
			}
			// For shape unification, accept the default; for other decisions
			// provide the expected responses.
			switch d.Kind {
			case DecideMapOrStruct:
				d.Response = Response{Name: "Root"}
			case DecideUnifyShapes:
				d.Response = d.Default
			case DecideShapeName:
				if d.ShapeIndex == 0 {
					d.Response = Response{Name: "FileField"}
				} else {
					d.Response = Response{Name: "FeatureField"}
				}
			default:
				d.Response = d.Default
			}
			return nil
		},
	})

	arr := []any{
		map[string]any{"slug": "a", "filename": "x.pdf", "is_required": true},
		map[string]any{"slug": "b", "feature": "upload", "archived": false},
	}
	obj := map[string]any{"items": arr}
	paths := sortPaths(a.Analyze(".", obj))

	if unifyDecision == nil {
		t.Fatal("expected DecideUnifyShapes decision")
	}
	if !unifyDecision.Default.IsNewType {
		t.Error("expected default IsNewType=true when unique fields dominate")
	}

	// Should have both FileField and FeatureField as separate types
	hasFile := false
	hasFeature := false
	for _, p := range paths {
		if strings.Contains(p, "{FileField}") {
			hasFile = true
		}
		if strings.Contains(p, "{FeatureField}") {
			hasFeature = true
		}
	}
	if !hasFile || !hasFeature {
		t.Errorf("expected both FileField and FeatureField types, got:\n  %s",
			strings.Join(paths, "\n  "))
	}
}

// TestDefaultSameWhenMeaningfulFieldsShared verifies that when shapes share
// many non-ubiquitous fields, the default response suggests same type.
func TestDefaultSameWhenMeaningfulFieldsShared(t *testing.T) {
	var unifyDecision *Decision
	a := New(AnalyzerConfig{
		Resolver: func(d *Decision) error {
			if d.Kind == DecideUnifyShapes && unifyDecision == nil {
				cp := *d
				unifyDecision = &cp
			}
			switch d.Kind {
			case DecideMapOrStruct:
				d.Response = Response{Name: "Root"}
			default:
				d.Response = d.Default
			}
			return nil
		},
	})

	arr := []any{
		map[string]any{"email": "a@b.com", "phone": "555", "address": "123 Main", "vip": true},
		map[string]any{"email": "c@d.com", "phone": "666", "address": "456 Oak", "score": jsonNum("42")},
	}
	obj := map[string]any{"people": arr}
	paths := sortPaths(a.Analyze(".", obj))

	if unifyDecision == nil {
		t.Fatal("expected DecideUnifyShapes decision")
	}
	if unifyDecision.Default.IsNewType {
		t.Error("expected default IsNewType=false when meaningful fields are shared")
	}

	// Should be unified as one type with optional fields
	typeCount := 0
	for _, p := range paths {
		if strings.Contains(p, "{People}") {
			typeCount++
		}
	}
	if typeCount == 0 {
		t.Errorf("expected People type (same default), got:\n  %s",
			strings.Join(paths, "\n  "))
	}
}

// TestIsUbiquitousField checks the ubiquitous field classifier.
func TestIsUbiquitousField(t *testing.T) {
	ubiquitous := []string{
		"id", "ID", "Id", "_id",
		"name", "Name",
		"type", "Type", "_type",
		"slug", "Slug",
		"label", "Label",
		"title", "Title",
		"created_at", "updated_at", "deleted_on",
		"startedAt", "endedOn",
	}
	for _, f := range ubiquitous {
		if !isUbiquitousField(f) {
			t.Errorf("expected %q to be ubiquitous", f)
		}
	}

	notUbiquitous := []string{
		"email", "phone", "address", "filename", "feature",
		"is_required", "archived", "score", "vip",
		"cat", "latitude", "url",
	}
	for _, f := range notUbiquitous {
		if isUbiquitousField(f) {
			t.Errorf("expected %q to NOT be ubiquitous", f)
		}
	}
}

// helpers

func jsonNum(s string) json.Number {
	return json.Number(s)
}

func assertPaths(t *testing.T, got, want []string) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("got %d paths, want %d:\n  got:  %s\n  want: %s",
			len(got), len(want), strings.Join(got, "\n        "), strings.Join(want, "\n        "))
		return
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("path[%d]: got %q, want %q", i, got[i], want[i])
		}
	}
}
