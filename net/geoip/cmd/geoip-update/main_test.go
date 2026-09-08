package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestParseFormat(t *testing.T) {
	for _, format := range []string{"pretty", "tsv", "csv", "json"} {
		got, err := parseFormat(format)
		if err != nil {
			t.Errorf("parseFormat(%q): %v", format, err)
		}
		if got != format {
			t.Errorf("parseFormat(%q) = %q, want %q", format, got, format)
		}
	}
	if _, err := parseFormat("yaml"); err == nil {
		t.Error("parseFormat(yaml): expected error")
	}
}

func TestWriteResultsTSVHasNoHeader(t *testing.T) {
	var out bytes.Buffer
	results := []result{{State: "updated", Edition: "GeoLite2-City", Path: "/tmp/city.tar.gz", Date: "2026-09-08"}}
	if err := writeResults(&out, "tsv", results); err != nil {
		t.Fatalf("writeResults: %v", err)
	}
	if strings.HasPrefix(out.String(), "state\t") {
		t.Fatalf("TSV has a header: %q", out.String())
	}
	if !strings.HasPrefix(out.String(), "updated\tGeoLite2-City\t") {
		t.Fatalf("TSV row = %q", out.String())
	}
}
