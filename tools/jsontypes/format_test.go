package jsontypes

import (
	"strings"
	"testing"
)

func TestParsePath(t *testing.T) {
	tests := []struct {
		path string
		want []segment
	}{
		{
			".{RoomsResult}.rooms[]{Room}.name{string}",
			[]segment{
				{name: "", typ: "RoomsResult"},
				{name: "rooms", index: "[]", typ: "Room"},
				{name: "name", typ: "string"},
			},
		},
		{
			".[string]{Person}.friends[]{Friend}.name{string}",
			[]segment{
				{name: "", index: "[string]", typ: "Person"},
				{name: "friends", index: "[]", typ: "Friend"},
				{name: "name", typ: "string"},
			},
		},
		{
			".{Root}.data[int][]{ResourceData}.x{string}",
			[]segment{
				{name: "", typ: "Root"},
				{name: "data", index: "[int][]", typ: "ResourceData"},
				{name: "x", typ: "string"},
			},
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

func TestFormatPaths(t *testing.T) {
	input := []string{
		".[person_id]{Person}.name{string}",
		".[person_id]{Person}.age{int}",
		".[person_id]{Person}.friends[]{Friend}.name{string}",
		".[person_id]{Person}.friends[]{Friend}.identification{null}",
		".[person_id]{Person}.friends[]{Friend}.identification{StateID}.number{string}",
	}
	got := FormatPaths(input)
	want := []string{
		"[person_id]{Person}",
		"[person_id].age{int}",
		"[person_id].friends[]{Friend}",
		"[person_id].friends[].identification{StateID?}",
		"[person_id].friends[].identification.number{string}",
		"[person_id].friends[].name{string}",
		"[person_id].name{string}",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\n  got:  %s\n  want: %s",
			len(got), len(want),
			strings.Join(got, "\n        "),
			strings.Join(want, "\n        "))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line[%d]:\n  got:  %s\n  want: %s", i, got[i], want[i])
		}
	}
}

// TestFormatPathsDifferentTypes verifies that when two different types exist
// at the same path position, their fields are grouped under the parent type
// and don't get deduplicated together.
func TestFormatPathsDifferentTypes(t *testing.T) {
	// Raw paths as produced by the analyzer when choosing "different" types
	input := []string{
		".{Root}.items[]{FileField}.slug{string}",
		".{Root}.items[]{FileField}.filename{string}",
		".{Root}.items[]{FileField}.is_required{bool}",
		".{Root}.items[]{FeatureField}.slug{string}",
		".{Root}.items[]{FeatureField}.feature{string}",
		".{Root}.items[]{FeatureField}.archived{bool}",
	}
	got := FormatPaths(input)
	want := []string{
		"{Root}",
		".items[]{FeatureField}",
		".items[]{FeatureField}.archived{bool}",
		".items[]{FeatureField}.feature{string}",
		".items[]{FeatureField}.slug{string}",
		".items[]{FileField}",
		".items[]{FileField}.filename{string}",
		".items[]{FileField}.is_required{bool}",
		".items[]{FileField}.slug{string}",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\n  got:  %s\n  want: %s",
			len(got), len(want),
			strings.Join(got, "\n        "),
			strings.Join(want, "\n        "))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line[%d]:\n  got:  %s\n  want: %s", i, got[i], want[i])
		}
	}
}

// TestDifferentTypesEndToEnd tests the full pipeline from JSON data through
// analysis with "different" type selection to formatted output.
func TestDifferentTypesEndToEnd(t *testing.T) {
	arr := []any{
		map[string]any{"slug": "a", "filename": "x.pdf", "is_required": true},
		map[string]any{"slug": "b", "filename": "y.pdf", "is_required": false},
		map[string]any{"slug": "c", "feature": "upload", "archived": false},
		map[string]any{"slug": "d", "feature": "export", "archived": true},
	}
	obj := map[string]any{"items": arr, "count": jsonNum("4"), "status": "ok"}

	a := New(AnalyzerConfig{
		// Root has 3 field-like keys → confident struct, no resolver call needed.
		// Then items[] has 2 shapes → unification: different types, then names.
		Resolver: scriptedResolver(
			Response{IsNewType: true},      // different types for shapes
			Response{Name: "FileField"},    // name for shape 1
			Response{Name: "FeatureField"}, // name for shape 2
		),
	})
	rawPaths := a.Analyze(".", obj)
	formatted := FormatPaths(rawPaths)

	// FileField and FeatureField should each have their own fields listed
	// under their type, not merged together
	fileFieldLines := 0
	featureFieldLines := 0
	for _, line := range formatted {
		if strings.Contains(line, "{FileField}") {
			fileFieldLines++
		}
		if strings.Contains(line, "{FeatureField}") {
			featureFieldLines++
		}
	}
	// FileField: intro + slug + filename + is_required = 4
	if fileFieldLines < 4 {
		t.Errorf("expected at least 4 FileField lines (intro + 3 fields), got %d:\n  %s",
			fileFieldLines, strings.Join(formatted, "\n  "))
	}
	// FeatureField: intro + slug + feature + archived = 4
	if featureFieldLines < 4 {
		t.Errorf("expected at least 4 FeatureField lines (intro + 3 fields), got %d:\n  %s",
			featureFieldLines, strings.Join(formatted, "\n  "))
	}
}

func TestFormatPathsRootStruct(t *testing.T) {
	input := []string{
		".{RoomsResult}.rooms[]{Room}.name{string}",
		".{RoomsResult}.errors[]{string}",
	}
	got := FormatPaths(input)
	want := []string{
		"{RoomsResult}",
		".errors[]{string}",
		".rooms[]{Room}",
		".rooms[].name{string}",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d lines, want %d:\n  got:  %s\n  want: %s",
			len(got), len(want),
			strings.Join(got, "\n        "),
			strings.Join(want, "\n        "))
	}
	for i := range got {
		if got[i] != want[i] {
			t.Errorf("line[%d]:\n  got:  %s\n  want: %s", i, got[i], want[i])
		}
	}
}
