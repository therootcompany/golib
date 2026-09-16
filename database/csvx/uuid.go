package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"

	"github.com/google/uuid"
)

// UUID is a nullable UUID that implements CSV, JSON, and driver interfaces.
type UUID struct {
	Bytes [16]byte
	Valid bool
}

func (u UUID) String() string {
	if !u.Valid {
		return ""
	}
	return uuid.UUID(u.Bytes).String()
}

func (u UUID) IsNil() bool { return !u.Valid }

func (u UUID) Value() (driver.Value, error) {
	if !u.Valid {
		return nil, nil
	}
	return u.String(), nil
}

func (u *UUID) Scan(value any) error {
	if value == nil {
		u.Valid = false
		u.Bytes = [16]byte{}
		return nil
	}
	switch v := value.(type) {
	case string:
		parsed, err := uuid.Parse(v)
		if err != nil {
			u.Valid = false
			u.Bytes = [16]byte{}
			return nil
		}
		copy(u.Bytes[:], parsed[:])
		u.Valid = true
	case []byte:
		if len(v) == 16 {
			copy(u.Bytes[:], v)
			u.Valid = true
			return nil
		}
		parsed, err := uuid.Parse(string(v))
		if err != nil {
			u.Valid = false
			u.Bytes = [16]byte{}
			return nil
		}
		copy(u.Bytes[:], parsed[:])
		u.Valid = true
	case UUID:
		*u = v
	default:
		return fmt.Errorf("csvx.UUID: cannot scan %T", value)
	}
	return nil
}

func (u UUID) MarshalCSV() ([]byte, error) {
	if !u.Valid {
		return nil, nil
	}
	return []byte(u.String()), nil
}

func (u *UUID) UnmarshalCSV(data []byte) error {
	s := string(data)
	if s == "" {
		u.Valid = false
		u.Bytes = [16]byte{}
		return nil
	}
	parsed, err := uuid.Parse(s)
	if err != nil {
		u.Valid = false
		u.Bytes = [16]byte{}
		return nil
	}
	copy(u.Bytes[:], parsed[:])
	u.Valid = true
	return nil
}

func (u UUID) MarshalJSON() ([]byte, error) {
	if !u.Valid {
		return []byte("null"), nil
	}
	return json.Marshal(u.String())
}

func (u *UUID) UnmarshalJSON(data []byte) error {
	if string(data) == "null" {
		u.Valid = false
		u.Bytes = [16]byte{}
		return nil
	}
	var s string
	if err := json.Unmarshal(data, &s); err != nil {
		return err
	}
	if s == "" {
		u.Valid = false
		u.Bytes = [16]byte{}
		return nil
	}
	parsed, err := uuid.Parse(s)
	if err != nil {
		u.Valid = false
		u.Bytes = [16]byte{}
		return nil
	}
	copy(u.Bytes[:], parsed[:])
	u.Valid = true
	return nil
}
