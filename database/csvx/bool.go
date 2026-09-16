package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Bool is a nullable boolean that implements CSV, JSON, and driver interfaces.
type Bool struct {
	Bool  bool
	Valid bool
}

func (b Bool) IsNil() bool { return !b.Valid }

func (b Bool) Value() (driver.Value, error) {
	if !b.Valid {
		return nil, nil
	}
	return b.Bool, nil
}

func (b *Bool) Scan(value any) error {
	if value == nil {
		b.Valid = false
		b.Bool = false
		return nil
	}
	switch v := value.(type) {
	case bool:
		b.Bool = v
		b.Valid = true
	case string:
		parsed, err := strconv.ParseBool(strings.TrimSpace(v))
		if err != nil {
			b.Valid = false
			b.Bool = false
			return nil
		}
		b.Bool = parsed
		b.Valid = true
	case []byte:
		return b.Scan(string(v))
	case Bool:
		*b = v
	default:
		return fmt.Errorf("csvx.Bool: cannot scan %T", value)
	}
	return nil
}

func (b Bool) MarshalCSV() ([]byte, error) {
	if !b.Valid {
		return nil, nil
	}
	return []byte(strconv.FormatBool(b.Bool)), nil
}

func (b *Bool) UnmarshalCSV(data []byte) error {
	s := strings.TrimSpace(string(data))
	if s == "" {
		b.Valid = false
		b.Bool = false
		return nil
	}
	parsed, err := strconv.ParseBool(s)
	if err != nil {
		b.Valid = false
		b.Bool = false
		return nil
	}
	b.Bool = parsed
	b.Valid = true
	return nil
}

func (b Bool) MarshalJSON() ([]byte, error) {
	if !b.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(b.Bool)
}

func (b *Bool) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		b.Valid = false
		b.Bool = false
		return nil
	}
	var v bool
	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}
	b.Bool = v
	b.Valid = true
	return nil
}
