package mcptypes

import (
	"encoding/json"
	"testing"
)

func TestIDishRoundTripsJSONRPCIDs(t *testing.T) {
	tests := []struct {
		name string
		json string
		csv  string
	}{
		{name: "null", json: "null", csv: ""},
		{name: "string", json: `"abc"`, csv: "abc"},
		{name: "integer", json: "9007199254740993", csv: "9007199254740993"},
		{name: "float", json: "1.25", csv: "1.25"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var id IDish
			if err := json.Unmarshal([]byte(tt.json), &id); err != nil {
				t.Fatal(err)
			}
			data, err := json.Marshal(id)
			if err != nil {
				t.Fatal(err)
			}
			if string(data) != tt.json {
				t.Fatalf("JSON = %s, want %s", data, tt.json)
			}
			csv, err := id.MarshalCSV()
			if err != nil {
				t.Fatal(err)
			}
			if csv != tt.csv {
				t.Fatalf("CSV = %q, want %q", csv, tt.csv)
			}
		})
	}
}

func TestIDishRejectsOtherJSONTypes(t *testing.T) {
	for _, input := range []string{`true`, `[]`, `{}`} {
		var id IDish
		if err := json.Unmarshal([]byte(input), &id); err == nil {
			t.Fatalf("Unmarshal(%s) succeeded, want error", input)
		}
	}
}

func TestMetaRoundTripPreservesExtensions(t *testing.T) {
	original := Meta{
		Values: map[string]any{"example.com/trace": "abc"},
		UI:     &AppUI{ResourceURI: "ui://example"},
	}

	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}

	var decoded Meta
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.Values["example.com/trace"] != "abc" {
		t.Fatalf("extension metadata was not preserved: %#v", decoded.Values)
	}
	if decoded.UI == nil || decoded.UI.ResourceURI != "ui://example" {
		t.Fatalf("UI metadata was not preserved: %#v", decoded.UI)
	}
}
