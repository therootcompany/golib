package csvx

import (
	"bytes"
	"encoding/csv"
	"testing"
)

func TestStringsCSV(t *testing.T) {
	var values Strings[Comma]
	if err := values.UnmarshalCSV([]byte("admin,hr,pm")); err != nil {
		t.Fatal(err)
	}
	data, err := values.MarshalCSV()
	if err != nil {
		t.Fatal(err)
	}
	if got := string(data); got != "admin,hr,pm" {
		t.Fatalf("CSV = %q", got)
	}

	var spaced Strings[Space]
	if err := spaced.UnmarshalCSV([]byte("admin hr\tpm")); err != nil {
		t.Fatal(err)
	}
	if len(spaced) != 3 || spaced[1] != "hr" {
		t.Fatalf("space values = %#v", spaced)
	}
}

func TestIntsJSONAndSQL(t *testing.T) {
	values := Ints[Comma]{1, 2, 3}
	got, err := values.Value()
	if err != nil {
		t.Fatal(err)
	}
	if string(got.([]byte)) != `[1,2,3]` {
		t.Fatalf("Value = %q", got)
	}

	var scanned Ints[Comma]
	if err := scanned.Scan([]byte(`[1,2,3]`)); err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 3 || scanned[2] != 3 {
		t.Fatalf("scanned = %#v", scanned)
	}
	if err := scanned.UnmarshalCSV([]byte("4,5,6")); err != nil {
		t.Fatal(err)
	}
	if len(scanned) != 3 || scanned[0] != 4 {
		t.Fatalf("CSV values = %#v", scanned)
	}
}

func TestDelimitedCSVUsesOuterQuoting(t *testing.T) {
	var data bytes.Buffer
	writer := csv.NewWriter(&data)
	writer.Comma = '\t'
	if err := SerializeCSV(writer, []struct {
		Values Strings[Tab] `json:"values"`
	}{{Values: Strings[Tab]{"a", "b"}}}); err != nil {
		t.Fatal(err)
	}
	if got := data.String(); got != "values\n\"a\tb\"\n" {
		t.Fatalf("TSV = %q", got)
	}
}
