package jsontypes

import (
	"strings"
	"testing"
)

func TestPipelineEndToEnd(t *testing.T) {
	// Test the full pipeline: JSON → RawPaths → Coalesce → GenerateGoStructs.
	data := loadJSONFixture(t, "testdata/swapi-luke.json")
	raw := RawPaths(data)
	coalesced := Coalesce(raw)

	// The coalesced output should be directly usable by the Go generator.
	goCode := GenerateGoStructs(coalesced)

	if goCode == "" {
		t.Fatal("GenerateGoStructs returned empty output")
	}

	// Should produce a Root struct with expected fields.
	if !strings.Contains(goCode, "type Root struct") {
		t.Error("missing Root struct")
	}
	if !strings.Contains(goCode, "`json:\"name\"`") {
		t.Error("missing name field")
	}
	if !strings.Contains(goCode, "`json:\"height\"`") {
		t.Error("missing height field")
	}

	t.Logf("Go output:\n%s", goCode)
}

func TestPipelinePokemon(t *testing.T) {
	data := loadJSONFixture(t, "testdata/pokemon-pikachu.json")
	raw := RawPaths(data)
	coalesced := Coalesce(raw)

	goCode := GenerateGoStructs(coalesced)

	if !strings.Contains(goCode, "type Root struct") {
		t.Error("missing Root struct")
	}
	if !strings.Contains(goCode, "type AbilitiesItem struct") {
		t.Error("missing AbilitiesItem struct")
	}
	if !strings.Contains(goCode, "type NameUrl struct") {
		t.Error("missing NameUrl struct")
	}

	// NameUrl should be used as a field type in multiple structs.
	nameUrlCount := strings.Count(goCode, "NameUrl")
	if nameUrlCount < 3 {
		t.Errorf("NameUrl used only %d times (expected many references)", nameUrlCount)
	}

	t.Logf("Go output (%d bytes, NameUrl used %d times):\n%s", len(goCode), nameUrlCount, goCode)
}

func TestPipelineSampleToGo(t *testing.T) {
	// Sample output should also work with the Go generator.
	data := loadJSONFixture(t, "testdata/swapi-planets.json")
	sample := SampleWithConfig(data, SampleConfig{MaxStringLen: 20})

	goCode := GenerateGoStructs(sample)

	if !strings.Contains(goCode, "type Root struct") {
		t.Error("missing Root struct")
	}
	if !strings.Contains(goCode, "type ResultsItem struct") {
		t.Error("missing ResultsItem struct")
	}

	t.Logf("Go output:\n%s", goCode)
}
