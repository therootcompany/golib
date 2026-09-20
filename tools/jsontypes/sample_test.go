package jsontypes

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestSampleBasic(t *testing.T) {
	input := `{"name":"Alice","age":30,"email":null}`
	var data any
	dec := json.NewDecoder(strings.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		t.Fatal(err)
	}

	got := Sample(data)

	// Type intro should have sample JSON.
	assertLineContains(t, got, "{Root:")
	// Leaf nodes should have actual values.
	assertLineContains(t, got, `.name{"Alice"}`)
	assertLineContains(t, got, ".age{30}")
	// Null should be preserved (email has both null and no other type → stays {null}).
	assertLineContains(t, got, ".email{null}")

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

func TestSampleTruncation(t *testing.T) {
	input := `{"bio":"This is a very long biography that should be truncated"}`
	var data any
	dec := json.NewDecoder(strings.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		t.Fatal(err)
	}

	got := SampleWithConfig(data, SampleConfig{MaxStringLen: 10})

	// Should be truncated with "..."
	assertLineContains(t, got, `"This is a "...`)

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

func TestSampleDedup(t *testing.T) {
	input := `{
		"author": {"name": "Alice", "url": "https://example.com/alice"},
		"reviewer": {"name": "Bob", "url": "https://example.com/bob"},
		"editor": {"name": "Carol", "url": "https://example.com/carol"}
	}`
	var data any
	dec := json.NewDecoder(strings.NewReader(input))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		t.Fatal(err)
	}

	got := Sample(data)

	// Three types with same keys {name, url} should be deduplicated.
	// Only one should have field expansion.
	nameCount := 0
	for _, line := range got {
		if strings.Contains(line, `.name{"`) {
			nameCount++
		}
	}
	if nameCount != 1 {
		t.Errorf("expected 1 name field (deduped), got %d", nameCount)
	}

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

func TestSamplePokemon(t *testing.T) {
	data := loadJSONFixture(t, "testdata/pokemon-pikachu.json")
	got := SampleWithConfig(data, SampleConfig{MaxStringLen: 30})

	// Should have compact JSON in type intros.
	assertLineContains(t, got, "{Root:")
	assertLineContains(t, got, "{AbilitiesItem:")
	assertLineContains(t, got, "{NameUrl:")

	// Should have actual values at leaves.
	assertLineContains(t, got, `.name{"pikachu"}`)
	assertLineContains(t, got, ".id{25}")

	t.Logf("sample output: %d lines", len(got))
}

func TestSampleCoalesceRoundTrip(t *testing.T) {
	// Sample output should be valid input for Coalesce.
	data := loadJSONFixture(t, "testdata/swapi-planets.json")
	sample := SampleWithConfig(data, SampleConfig{MaxStringLen: 20})

	// Feed sample output back through Coalesce — should be idempotent.
	coalesced := Coalesce(sample)

	if len(coalesced) != len(sample) {
		t.Errorf("re-coalescing changed line count: %d → %d", len(sample), len(coalesced))
	}

	t.Logf("sample: %d lines, re-coalesced: %d lines", len(sample), len(coalesced))
}

func loadJSONFixture(t *testing.T, path string) any {
	t.Helper()
	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer f.Close()

	var data any
	dec := json.NewDecoder(f)
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		t.Fatalf("decode %s: %v", path, err)
	}
	return data
}
