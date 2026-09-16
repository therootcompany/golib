package csvx

import (
	"bytes"
	"encoding/json"
	"fmt"
)

// RawJSON holds a JSON document as raw bytes. CSV/TSV encode it as JSON
// text, JSON encoding passes it through unchanged, and jsonb binds it as
// bytes.
type RawJSON json.RawMessage

// MarshalJSON renders the stored document verbatim.
func (r RawJSON) MarshalJSON() ([]byte, error) {
	if len(bytes.TrimSpace(r)) == 0 {
		return []byte("null"), nil
	}
	return r, nil
}

// UnmarshalJSON stores the document verbatim after validation.
func (r *RawJSON) UnmarshalJSON(data []byte) error {
	if len(bytes.TrimSpace(data)) == 0 {
		*r = nil
		return nil
	}
	if !json.Valid(data) {
		return fmt.Errorf("csvx: not valid JSON: %q", bytes.TrimSpace(data))
	}
	*r = RawJSON(append([]byte(nil), data...))
	return nil
}

// MarshalCSV renders the document as JSON text.
func (r RawJSON) MarshalCSV() ([]byte, error) { return r, nil }

// UnmarshalCSV stores the field as the JSON document.
func (r *RawJSON) UnmarshalCSV(data []byte) error { return r.UnmarshalJSON(data) }

// String returns the document as a string.
func (r RawJSON) String() string { return string(r) }
