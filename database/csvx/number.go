package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
)

// Float64 is a nullable float that implements CSV, JSON, and driver interfaces.
type Float64 struct {
	Float64 float64
	Valid   bool
}

func (v Float64) Value() (driver.Value, error) {
	if !v.Valid {
		return nil, nil
	}
	return v.Float64, nil
}

func (v *Float64) Scan(value any) error {
	if value == nil {
		v.Float64, v.Valid = 0, false
		return nil
	}
	switch x := value.(type) {
	case float64:
		v.Float64, v.Valid = x, true
	case int64:
		v.Float64, v.Valid = float64(x), true
	case []byte:
		return v.Scan(string(x))
	case string:
		parsed, err := strconv.ParseFloat(x, 64)
		if err != nil {
			return fmt.Errorf("csvx.Float64: %w", err)
		}
		v.Float64, v.Valid = parsed, true
	case Float64:
		*v = x
	default:
		return fmt.Errorf("csvx.Float64: cannot scan %T", value)
	}
	return nil
}

func (v Float64) MarshalCSV() ([]byte, error) {
	if !v.Valid {
		return nil, nil
	}
	return []byte(strconv.FormatFloat(v.Float64, 'g', -1, 64)), nil
}

func (v *Float64) UnmarshalCSV(data []byte) error {
	if len(data) == 0 {
		v.Float64, v.Valid = 0, false
		return nil
	}
	return v.Scan(string(data))
}

func (v Float64) MarshalJSON() ([]byte, error) {
	if !v.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(v.Float64)
}

func (v *Float64) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		v.Float64, v.Valid = 0, false
		return nil
	}
	var parsed float64
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	v.Float64, v.Valid = parsed, true
	return nil
}

// Int64 is a nullable integer that implements CSV, JSON, and driver interfaces.
type Int64 struct {
	Int64 int64
	Valid bool
}

func (v Int64) Value() (driver.Value, error) {
	if !v.Valid {
		return nil, nil
	}
	return v.Int64, nil
}

func (v *Int64) Scan(value any) error {
	if value == nil {
		v.Int64, v.Valid = 0, false
		return nil
	}
	switch x := value.(type) {
	case int64:
		v.Int64, v.Valid = x, true
	case int:
		v.Int64, v.Valid = int64(x), true
	case []byte:
		return v.Scan(string(x))
	case string:
		parsed, err := strconv.ParseInt(x, 10, 64)
		if err != nil {
			return fmt.Errorf("csvx.Int64: %w", err)
		}
		v.Int64, v.Valid = parsed, true
	case Int64:
		*v = x
	default:
		return fmt.Errorf("csvx.Int64: cannot scan %T", value)
	}
	return nil
}

func (v Int64) MarshalCSV() ([]byte, error) {
	if !v.Valid {
		return nil, nil
	}
	return []byte(strconv.FormatInt(v.Int64, 10)), nil
}

func (v *Int64) UnmarshalCSV(data []byte) error {
	if len(data) == 0 {
		v.Int64, v.Valid = 0, false
		return nil
	}
	return v.Scan(string(data))
}

func (v Int64) MarshalJSON() ([]byte, error) {
	if !v.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(v.Int64)
}

func (v *Int64) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		v.Int64, v.Valid = 0, false
		return nil
	}
	var parsed int64
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	v.Int64, v.Valid = parsed, true
	return nil
}
