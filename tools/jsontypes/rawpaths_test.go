package jsontypes

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestRawPathsFixtures(t *testing.T) {
	tests := []struct {
		name string
		file string
		// Spot-check: paths that must appear in the output.
		mustContain []string
		// No struct-explosion: output should be under this many lines.
		maxLines int
	}{
		{
			name: "pokemon",
			file: "testdata/pokemon-pikachu.json",
			mustContain: []string{
				"{Root0}",
				".name{string}",
				".abilities[]{AbilitiesItem",
				".stats[]{StatsItem",
				".types[]{TypesItem",
				".sprites{Sprite",
			},
			maxLines: 250,
		},
		{
			name: "swapi_person",
			file: "testdata/swapi-luke.json",
			mustContain: []string{
				"{Root0}",
				".name{string}",
				".height{string}",
				".films[]{string}",
			},
			maxLines: 30,
		},
		{
			name: "swapi_planets",
			file: "testdata/swapi-planets.json",
			mustContain: []string{
				"{Root0}",
				".count{int}",
				".results[]{ResultsItem",
				"climate{string}",
				"population{string}",
			},
			maxLines: 30,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f, err := os.Open(tt.file)
			if err != nil {
				t.Fatalf("open %s: %v", tt.file, err)
			}
			defer f.Close()

			var data any
			dec := json.NewDecoder(f)
			dec.UseNumber()
			if err := dec.Decode(&data); err != nil {
				t.Fatalf("decode: %v", err)
			}

			paths := RawPaths(data)

			if len(paths) > tt.maxLines {
				t.Errorf("too many paths: got %d, max %d (possible struct explosion)",
					len(paths), tt.maxLines)
			}

			for _, want := range tt.mustContain {
				found := false
				for _, p := range paths {
					if strings.Contains(p, want) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("missing expected path containing %q", want)
				}
			}

			t.Logf("%d paths from %s", len(paths), tt.file)
		})
	}
}
