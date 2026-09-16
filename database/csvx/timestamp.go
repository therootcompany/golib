package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Timestamp is a nullable timestamp (without timezone) that implements CSV,
// JSON, and driver interfaces.
type Timestamp struct {
	Time  time.Time
	Valid bool
}

func (t Timestamp) IsNil() bool { return !t.Valid }

func (t Timestamp) Value() (driver.Value, error) {
	if !t.Valid {
		return nil, nil
	}
	return t.Time, nil
}

func (t *Timestamp) Scan(value any) error {
	if value == nil {
		t.Valid = false
		t.Time = time.Time{}
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		t.Time = v
		t.Valid = true
	case string:
		parsed, err := parseTimestamp(v)
		if err != nil {
			t.Valid = false
			t.Time = time.Time{}
			return nil
		}
		t.Time = parsed
		t.Valid = true
	case []byte:
		return t.Scan(string(v))
	case Timestamp:
		*t = v
	default:
		return fmt.Errorf("csvx.Timestamp: cannot scan %T", value)
	}
	return nil
}

func (t Timestamp) MarshalCSV() ([]byte, error) {
	if !t.Valid {
		return nil, nil
	}
	return []byte(t.Time.Format(time.RFC3339Nano)), nil
}

func (t *Timestamp) UnmarshalCSV(data []byte) error {
	s := string(data)
	if s == "" {
		t.Valid = false
		t.Time = time.Time{}
		return nil
	}
	parsed, err := parseTimestamp(s)
	if err != nil {
		t.Valid = false
		t.Time = time.Time{}
		return nil
	}
	t.Time = parsed
	t.Valid = true
	return nil
}

func (t Timestamp) MarshalJSON() ([]byte, error) {
	if !t.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(t.Time.Format(time.RFC3339Nano))
}

func (t *Timestamp) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		t.Valid = false
		t.Time = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		t.Valid = false
		t.Time = time.Time{}
		return nil
	}
	parsed, err := parseTimestamp(s)
	if err != nil {
		t.Valid = false
		t.Time = time.Time{}
		return nil
	}
	t.Time = parsed
	t.Valid = true
	return nil
}

func parseTimestamp(s string) (time.Time, error) {
	for _, layout := range []string{time.RFC3339Nano, time.RFC3339, "2006-01-02 15:04:05", "2006-01-02"} {
		if parsed, err := time.Parse(layout, s); err == nil {
			return parsed, nil
		}
	}
	return time.Time{}, fmt.Errorf("csvx.Timestamp: unrecognized time %q", s)
}
