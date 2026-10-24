package csvx

import "testing"

func TestIsBoolNull(t *testing.T) {
	for _, null := range []string{"", "  ", "null", "NULL", "Null", " null ", `\null`, `\NULL`, `\N`, "none", "None", "unknown", "UNKNOWN"} {
		if !isBoolNull(null) {
			t.Errorf("isBoolNull(%q) = false, want true", null)
		}
	}
	// Everything else is a value, not a null.
	for _, value := range []string{`\n`, `N`, `N\`, "none of the above", "nullable", "no", "off", "na", "disable", "disabled", "NULLITY"} {
		if isBoolNull(value) {
			t.Errorf("isBoolNull(%q) = true, want false", value)
		}
	}
}

func TestBoolCSVNullSentinels(t *testing.T) {
	// Bool must read the same null sentinels as BoolishTimestamp (isBoolNull)
	// explicitly rather than relying on ParseBool failing: the PG dump
	// sentinel and a representative word.
	for _, null := range []string{`\N`, "none"} {
		var b Bool
		if err := b.UnmarshalCSV([]byte(null)); err != nil {
			t.Fatalf("UnmarshalCSV(%q): %v", null, err)
		}
		if b.Valid || b.Bool {
			t.Errorf("UnmarshalCSV(%q) = %+v, want absent", null, b)
		}
		var b2 Bool
		if err := b2.Scan(null); err != nil {
			t.Fatalf("Scan(%q): %v", null, err)
		}
		if b2.Valid || b2.Bool {
			t.Errorf("Scan(%q) = %+v, want absent", null, b2)
		}
	}
	// `\n` (lowercase) is not the sentinel: it parses as unrecognized.
	var b Bool
	if err := b.Scan(`\n`); err != nil {
		t.Fatalf("Scan: %v", err)
	}
	if b.Valid || b.Bool {
		t.Errorf(`Scan(\n) = %+v, want absent`, b)
	}
	// Real values still parse; a non-sentinel word is unrecognized.
	if err := b.UnmarshalCSV([]byte("true")); err != nil {
		t.Fatalf("UnmarshalCSV(true): %v", err)
	}
	if !b.Valid || !b.Bool {
		t.Errorf("UnmarshalCSV(true) = %+v", b)
	}
}
