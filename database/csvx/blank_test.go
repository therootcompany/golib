package csvx

import (
	"encoding/csv"
	"strings"
	"testing"
)

type blankRec struct {
	A string `json:"a"`
	B string `json:"b"`
}

func parseBlank[T any](in string) ([]T, error) {
	c := csv.NewReader(strings.NewReader(in))
	c.FieldsPerRecord = -1 // ragged-tolerant, as sheet readers configure
	return ParseCSV[T](c)
}

// Leading blank rows must not be taken as the header (Google Sheets
// exports with an empty row 1).
func TestParseCSVBlankHeaderRow(t *testing.T) {
	items, err := parseBlank[blankRec](",,,,\r\n\r\na,b\r\n1,x\r\n2,y\r\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	want := []blankRec{{A: "1", B: "x"}, {A: "2", B: "y"}}
	if len(items) != len(want) {
		t.Fatalf("rows: %d, want %d (%+v)", len(items), len(want), items)
	}
	for i := range want {
		if items[i] != want[i] {
			t.Errorf("row %d: %+v, want %+v", i, items[i], want[i])
		}
	}
}

// Blank and whitespace-only data rows are skipped.
func TestParseCSVBlankDataRows(t *testing.T) {
	items, err := parseBlank[blankRec]("a,b\r\n1,x\r\n\r\n   ,\r\n2,y\r\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(items) != 2 || items[0] != (blankRec{A: "1", B: "x"}) || items[1] != (blankRec{A: "2", B: "y"}) {
		t.Fatalf("rows: %+v", items)
	}
}

// Normal input is unchanged.
func TestParseCSVNoBlanks(t *testing.T) {
	items, err := parseBlank[blankRec]("a,b\r\n1,x\r\n2,y\r\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(items) != 2 || items[1] != (blankRec{A: "2", B: "y"}) {
		t.Fatalf("rows: %+v", items)
	}
}

// TSV: blank header row with tab delimiter.
func TestParseCSVBlankHeaderTSV(t *testing.T) {
	in := "\t\t\r\na\tb\r\n1\tx\r\n"
	c := csv.NewReader(strings.NewReader(in))
	c.Comma = '\t'
	c.FieldsPerRecord = -1
	items, err := ParseCSV[blankRec](c)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(items) != 1 || items[0] != (blankRec{A: "1", B: "x"}) {
		t.Fatalf("rows: %+v", items)
	}
}

// All-blank input: no header, no rows.
func TestParseCSVAllBlank(t *testing.T) {
	items, err := parseBlank[blankRec]("\r\n,\r\n")
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if items != nil {
		t.Fatalf("rows: %+v, want nil", items)
	}
}
