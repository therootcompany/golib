package csvx

import "testing"

func TestTextishNormalizesExplicitEmptyValues(t *testing.T) {
	for _, value := range []string{"", "none", "disable", "disabled", " NONE "} {
		var got Textish
		if err := got.UnmarshalCSV([]byte(value)); err != nil {
			t.Fatal(err)
		}
		if !got.Empty() {
			t.Fatalf("Textish(%q) = %q, want empty", value, got)
		}
	}
	var got Textish
	if err := got.UnmarshalCSV([]byte("https://hooks.example.test/enrich")); err != nil {
		t.Fatal(err)
	}
	if got.String() != "https://hooks.example.test/enrich" {
		t.Fatalf("Textish URL = %q", got)
	}
}
