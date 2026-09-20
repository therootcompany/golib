package jsontypes

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestCoalesceBasic(t *testing.T) {
	input := []string{
		"{Root0}",
		".name{string}",
		".email{string}",
		".email{null}",
		".friends[]{FriendsItem1}",
		".friends[].name{string}",
		".friends[].age{int}",
	}

	got := Coalesce(input)

	// Root0 → Root (unique)
	assertLineContains(t, got, "{Root}")
	// email should be {string?} (nullable)
	assertLineContains(t, got, ".email{string?}")
	// standalone {null} should be removed
	assertLineNotContains(t, got, ".email{null}")
	// FriendsItem1 → FriendsItem (unique)
	assertLineContains(t, got, ".friends[]{FriendsItem}")

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

func TestCoalesceDedup(t *testing.T) {
	// Two types with the same key set at different paths.
	input := []string{
		"{Root0}",
		".author{Author1}",
		".author.name{string}",
		".author.url{string}",
		".reviewer{Reviewer2}",
		".reviewer.name{string}",
		".reviewer.url{string}",
	}

	got := Coalesce(input)

	// Both Author and Reviewer have {name, url} → merged into one type.
	// Only one should have fields expanded.
	nameUrlCount := 0
	fieldCount := 0
	for _, line := range got {
		if strings.Contains(line, ".name{string}") {
			fieldCount++
		}
		if strings.Contains(line, "{Author}") || strings.Contains(line, "{Reviewer}") {
			nameUrlCount++
		}
	}

	// The canonical name should appear at both paths.
	if nameUrlCount != 2 {
		t.Errorf("expected 2 references to canonical type, got %d", nameUrlCount)
	}

	// But fields should only appear once (for the first occurrence).
	if fieldCount != 1 {
		t.Errorf("expected 1 field expansion, got %d", fieldCount)
	}

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

func TestCoalesceDedupManyNames(t *testing.T) {
	// >2 distinct base names with same key set → derive name from keys.
	input := []string{
		"{Root0}",
		".ability{Ability1}",
		".ability.name{string}",
		".ability.url{string}",
		".version{Version2}",
		".version.name{string}",
		".version.url{string}",
		".species{Species3}",
		".species.name{string}",
		".species.url{string}",
	}

	got := Coalesce(input)

	// 3 distinct base names → derived name "NameUrl".
	assertLineContains(t, got, "{NameUrl}")
	// Fields expanded only once.
	nameCount := 0
	for _, line := range got {
		if strings.HasSuffix(line, ".name{string}") {
			nameCount++
		}
	}
	if nameCount != 1 {
		t.Errorf("expected 1 .name{string} (deduped), got %d", nameCount)
	}

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

func TestCoalesceUndefinedCollapses(t *testing.T) {
	input := []string{
		"[]{RootItem0}",
		"[].name{string}",
		"[].email{undefined}",
		"[].email{string}",
	}

	got := Coalesce(input)

	// {undefined} collapses into ? on the concrete type (same as null).
	assertLineContains(t, got, "[].email{string?}")
	assertLineNotContains(t, got, "[].email{undefined}")
	assertLineNotContains(t, got, "[].email{string}")

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

func TestCoalesceNullAndUndefinedBothCollapse(t *testing.T) {
	input := []string{
		"[]{RootItem0}",
		"[].email{undefined}",
		"[].email{null}",
		"[].email{string}",
	}

	got := Coalesce(input)

	// Both {undefined} and {null} collapse into {string?}.
	assertLineContains(t, got, "[].email{string?}")
	assertLineNotContains(t, got, "[].email{undefined}")
	assertLineNotContains(t, got, "[].email{null}")

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

func TestCoalescePokemonFixture(t *testing.T) {
	lines := rawPathsFromFixture(t, "testdata/pokemon-pikachu.json")
	got := Coalesce(lines)

	// Should be significantly fewer lines than the raw output.
	if len(got) >= len(lines) {
		t.Errorf("coalesced output (%d lines) should be fewer than raw (%d lines)",
			len(got), len(lines))
	}

	// {name, url} types should be merged (many types share this shape).
	assertLineContains(t, got, "{NameUrl}")

	// Root should lose its number.
	assertLineContains(t, got, "{Root}")

	// Core structure preserved.
	assertLineContains(t, got, ".abilities[]{AbilitiesItem}")
	assertLineContains(t, got, ".stats[]{StatsItem}")
	assertLineContains(t, got, ".types[]{TypesItem}")

	// Nullable fields: dream_world.front_female is null in some contexts.
	// (In single-document mode, null-only fields stay as {null}.)

	t.Logf("raw: %d lines → coalesced: %d lines", len(lines), len(got))
	t.Logf("output:\n%s", strings.Join(got, "\n"))
}

func TestCoalesceSWAPIPlanets(t *testing.T) {
	lines := rawPathsFromFixture(t, "testdata/swapi-planets.json")
	got := Coalesce(lines)

	// Root should be clean.
	assertLineContains(t, got, "{Root}")
	assertLineContains(t, got, ".results[]{ResultsItem}")

	// No nullable fields in this fixture (previous is null but standalone).
	assertLineContains(t, got, ".previous{null}")

	t.Logf("raw: %d lines → coalesced: %d lines", len(lines), len(got))
	t.Logf("output:\n%s", strings.Join(got, "\n"))
}

func TestCoalescePerBaseNameNumbering(t *testing.T) {
	// Two types with the same base name but different key sets.
	input := []string{
		"{Root0}",
		".config{Settings1}",
		".config.host{string}",
		".config.port{int}",
		".prefs{Settings2}",
		".prefs.theme{string}",
		".prefs.lang{string}",
		".prefs.debug{bool}",
	}

	got := Coalesce(input)

	// Both are "Settings" base but different keys → numbered.
	assertLineContains(t, got, ".config{Settings0}")
	assertLineContains(t, got, ".prefs{Settings1}")

	t.Logf("output (%d lines):\n%s", len(got), strings.Join(got, "\n"))
}

// Helper: run RawPaths on a fixture file and return the lines.
func rawPathsFromFixture(t *testing.T, path string) []string {
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
		t.Fatalf("decode: %v", err)
	}

	return RawPaths(data)
}

func assertLineContains(t *testing.T, lines []string, want string) {
	t.Helper()
	for _, line := range lines {
		if strings.Contains(line, want) {
			return
		}
	}
	t.Errorf("missing expected line containing %q", want)
}

func assertLineNotContains(t *testing.T, lines []string, want string) {
	t.Helper()
	for _, line := range lines {
		if line == want {
			t.Errorf("unexpected line %q", want)
			return
		}
	}
}
