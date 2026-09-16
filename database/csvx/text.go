package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
)

// Text is a nullable string that implements CSV, JSON, and driver interfaces.
type Text struct {
	String string
	Valid  bool
}

func (t Text) IsNil() bool { return !t.Valid }

func (t Text) Value() (driver.Value, error) {
	if !t.Valid {
		return nil, nil
	}
	return t.String, nil
}

func (t *Text) Scan(value any) error {
	if value == nil {
		t.Valid = false
		t.String = ""
		return nil
	}
	switch v := value.(type) {
	case string:
		t.String = v
		t.Valid = true
	case []byte:
		t.String = string(v)
		t.Valid = true
	case Text:
		*t = v
	default:
		return fmt.Errorf("csvx.Text: cannot scan %T", value)
	}
	return nil
}

func (t Text) MarshalCSV() ([]byte, error) {
	if !t.Valid {
		return nil, nil
	}
	return []byte(t.String), nil
}

func (t *Text) UnmarshalCSV(data []byte) error {
	s := string(data)
	if s == "" {
		t.Valid = false
		t.String = ""
		return nil
	}
	t.String = s
	t.Valid = true
	return nil
}

func (t Text) MarshalJSON() ([]byte, error) {
	if !t.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(t.String)
}

func (t *Text) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		t.Valid = false
		t.String = ""
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		t.Valid = false
		t.String = ""
		return nil
	}
	t.String = s
	t.Valid = true
	return nil
}
