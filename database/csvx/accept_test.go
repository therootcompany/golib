package csvx

import (
	"net/http/httptest"
	"testing"
)

func TestAcceptFormat(t *testing.T) {
	for _, tc := range []struct {
		accept, want string
	}{
		{"application/json", "json"},
		{"text/csv", "csv"},
		{"text/tab-separated-values", "tab"},
		{"application/x-ndjson", "jsonl"},
		{"*/*", "csv"},
		{"", "csv"},
		{"text/html", "csv"},
		{"application/json;q=0.5, text/csv", "csv"},
		{"text/csv;q=0.5, application/json", "json"},
	} {
		r := httptest.NewRequest("GET", "/x", nil)
		r.Header.Set("Accept", tc.accept)
		got, err := ResolveFormat(r)
		if err != nil || string(got) != tc.want {
			t.Errorf("Accept=%q → %q (err %v), want %q", tc.accept, got, err, tc.want)
		}
	}
}

func TestAcceptFormatDirect(t *testing.T) {
	got, err := acceptFormat("application/json")
	t.Logf("acceptFormat(application/json) = %q, %v", got, err)
	if string(got) != "json" {
		t.Fatalf("want json, got %q", got)
	}
}
