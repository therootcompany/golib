package csvx

import (
	"fmt"
	"strings"
	"time"
)

// BoolishTimestamp accepts optional true/false-like values and dates or
// timestamps from human-edited CSV/TSV data. Valid reports that a value was
// supplied; Bool reports its true-like meaning. Error records an unrecognized
// non-empty value without making the CSV decoder reject the row.
type BoolishTimestamp struct {
	Valid     bool
	Bool      bool
	Timestamp time.Time
	Error     error
}

// UnmarshalCSV parses a human value. Unknown non-empty values are retained as
// errors so the collection mapper can apply its own conservative policy.
func (v *BoolishTimestamp) UnmarshalCSV(data []byte) error {
	*v = BoolishTimestamp{}
	raw := strings.TrimSpace(string(data))
	if raw == "" || strings.EqualFold(raw, "null") || raw == `\N` {
		return nil
	}
	v.Valid = true
	switch strings.ToLower(raw) {
	case "false", "f", "n", "no", "0":
		return nil
	case "true", "t", "y", "yes", "1", "disabled", "disable":
		v.Bool = true
		return nil
	}
	for _, layout := range []string{time.RFC3339, "2006-01-02", "2006-01-02 15:04:05Z07:00", "2006-01-02 15:04:05"} {
		parsed, err := time.Parse(layout, raw)
		if err == nil {
			v.Bool = true
			v.Timestamp = parsed
			return nil
		}
	}
	v.Bool = true
	v.Error = fmt.Errorf("unrecognized boolish timestamp %q", raw)
	return nil
}

// MarshalCSV writes a normalized usable record. An unrecognized value is
// conservatively serialized as the current UTC timestamp.
func (v BoolishTimestamp) MarshalCSV() ([]byte, error) {
	if !v.Valid {
		return nil, nil
	}
	if v.Error != nil {
		return []byte(time.Now().UTC().Format("2006-01-02 15:04:05")), nil
	}
	if !v.Bool {
		return []byte("FALSE"), nil
	}
	if !v.Timestamp.IsZero() {
		return []byte(v.Timestamp.UTC().Format("2006-01-02 15:04:05")), nil
	}
	return []byte("TRUE"), nil
}

// IsZero lets encoders treat the zero value as an omitted source value.
func (v BoolishTimestamp) IsZero() bool { return !v.Valid }
