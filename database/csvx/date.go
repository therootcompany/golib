package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"time"
)

// Date is a nullable date that implements CSV, JSON, and driver interfaces.
type Date struct {
	Time  time.Time
	Valid bool
}

const dateFormat = "2006-01-02"

func (d Date) IsNil() bool { return !d.Valid }

func (d Date) Value() (driver.Value, error) {
	if !d.Valid {
		return nil, nil
	}
	return d.Time, nil
}

func (d *Date) Scan(value any) error {
	if value == nil {
		d.Valid = false
		d.Time = time.Time{}
		return nil
	}
	switch v := value.(type) {
	case time.Time:
		d.Time = v
		d.Valid = true
	case string:
		parsed, err := time.Parse(dateFormat, v)
		if err != nil {
			d.Valid = false
			d.Time = time.Time{}
			return nil
		}
		d.Time = parsed
		d.Valid = true
	case []byte:
		return d.Scan(string(v))
	case Date:
		*d = v
	default:
		return fmt.Errorf("csvx.Date: cannot scan %T", value)
	}
	return nil
}

func (d Date) MarshalCSV() ([]byte, error) {
	if !d.Valid {
		return nil, nil
	}
	return []byte(d.Time.Format(dateFormat)), nil
}

func (d *Date) UnmarshalCSV(data []byte) error {
	s := string(data)
	if s == "" {
		d.Valid = false
		d.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(dateFormat, s)
	if err != nil {
		d.Valid = false
		d.Time = time.Time{}
		return nil
	}
	d.Time = parsed
	d.Valid = true
	return nil
}

func (d Date) MarshalJSON() ([]byte, error) {
	if !d.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(d.Time.Format(dateFormat))
}

func (d *Date) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		d.Valid = false
		d.Time = time.Time{}
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		d.Valid = false
		d.Time = time.Time{}
		return nil
	}
	parsed, err := time.Parse(dateFormat, s)
	if err != nil {
		d.Valid = false
		d.Time = time.Time{}
		return nil
	}
	d.Time = parsed
	d.Valid = true
	return nil
}
