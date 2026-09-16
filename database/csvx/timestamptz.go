package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Timestamptz is a nullable timestamp with timezone that implements CSV,
// JSON, and driver interfaces. Time is stored in UTC.
type Timestamptz struct {
	Time  time.Time
	Valid bool
}

func (t Timestamptz) IsNil() bool { return !t.Valid }

func (t Timestamptz) Value() (driver.Value, error) {
	if !t.Valid {
		return nil, nil
	}
	return t.Time.UTC(), nil
}

func (t *Timestamptz) Scan(value any) error {
	if value == nil {
		t.Valid = false
		t.Time = time.Time{}
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		t.Time = v.UTC()
		t.Valid = true
	case string:
		parsed, err := parseTimestamp(v)
		if err != nil {
			t.Valid = false
			t.Time = time.Time{}
			return nil
		}
		t.Time = parsed.UTC()
		t.Valid = true
	case []byte:
		return t.Scan(string(v))
	case Timestamptz:
		*t = v
	default:
		return fmt.Errorf("csvx.Timestamptz: cannot scan %T", value)
	}
	return nil
}

func (t Timestamptz) MarshalCSV() ([]byte, error) {
	if !t.Valid {
		return nil, nil
	}
	return []byte(t.Time.UTC().Format(time.RFC3339Nano)), nil
}

func (t *Timestamptz) UnmarshalCSV(data []byte) error {
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
	t.Time = parsed.UTC()
	t.Valid = true
	return nil
}

func (t Timestamptz) MarshalJSON() ([]byte, error) {
	if !t.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(t.Time.UTC().Format(time.RFC3339Nano))
}

func (t *Timestamptz) UnmarshalJSON(data []byte) error {
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
	t.Time = parsed.UTC()
	t.Valid = true
	return nil
}
