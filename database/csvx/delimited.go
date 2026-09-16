package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// Delimiter selects the separator used by a delimited value's CSV form.
type Delimiter interface {
	Separator() string
}

// Comma separates values with a comma.
type Comma struct{}

func (Comma) Separator() string { return "," }

// Space separates values with whitespace.
type Space struct{}

func (Space) Separator() string { return " " }

// Tab separates values with a tab.
type Tab struct{}

func (Tab) Separator() string { return "\t" }

// Strings is a string slice with a delimiter-specific CSV form.
// Its SQL and JSON forms are JSON arrays.
type Strings[D Delimiter] []string

// Value implements driver.Valuer as a JSON array.
func (s Strings[D]) Value() (driver.Value, error) {
	if s == nil {
		s = Strings[D]{}
	}
	return json.Marshal([]string(s))
}

// Scan implements sql.Scanner from a JSON array.
func (s *Strings[D]) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		*s = nil
		return nil
	case []byte:
		return s.scanJSON(v)
	case string:
		return s.scanJSON([]byte(v))
	case Strings[D]:
		*s = append((*s)[:0], v...)
		return nil
	default:
		return fmt.Errorf("csvx.Strings: cannot scan %T", value)
	}
}

func (s *Strings[D]) scanJSON(data []byte) error {
	if len(data) == 0 {
		*s = nil
		return nil
	}
	var values []string
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("csvx.Strings: %w", err)
	}
	*s = values
	return nil
}

// MarshalCSV implements csvutil.Marshaler.
func (s Strings[D]) MarshalCSV() ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}
	var delimiter D
	return []byte(strings.Join(s, delimiter.Separator())), nil
}

// UnmarshalCSV implements csvutil.Unmarshaler.
func (s *Strings[D]) UnmarshalCSV(data []byte) error {
	if len(data) == 0 {
		*s = nil
		return nil
	}
	var delimiter D
	if delimiter.Separator() == (Space{}).Separator() {
		*s = Strings[D](strings.Fields(string(data)))
		return nil
	}
	*s = Strings[D](strings.Split(string(data), delimiter.Separator()))
	return nil
}

// Ints is an int64 slice with a delimiter-specific CSV form.
// Its SQL and JSON forms are JSON arrays.
type Ints[D Delimiter] []int64

// Value implements driver.Valuer as a JSON array.
func (s Ints[D]) Value() (driver.Value, error) {
	if s == nil {
		s = Ints[D]{}
	}
	return json.Marshal([]int64(s))
}

// Scan implements sql.Scanner from a JSON array.
func (s *Ints[D]) Scan(value any) error {
	switch v := value.(type) {
	case nil:
		*s = nil
		return nil
	case []byte:
		return s.scanJSON(v)
	case string:
		return s.scanJSON([]byte(v))
	case Ints[D]:
		*s = append((*s)[:0], v...)
		return nil
	default:
		return fmt.Errorf("csvx.Ints: cannot scan %T", value)
	}
}

func (s *Ints[D]) scanJSON(data []byte) error {
	if len(data) == 0 {
		*s = nil
		return nil
	}
	var values []int64
	if err := json.Unmarshal(data, &values); err != nil {
		return fmt.Errorf("csvx.Ints: %w", err)
	}
	*s = values
	return nil
}

// MarshalCSV implements csvutil.Marshaler.
func (s Ints[D]) MarshalCSV() ([]byte, error) {
	if len(s) == 0 {
		return nil, nil
	}
	var delimiter D
	values := make([]string, len(s))
	for i, value := range s {
		values[i] = strconv.FormatInt(value, 10)
	}
	return []byte(strings.Join(values, delimiter.Separator())), nil
}

// UnmarshalCSV implements csvutil.Unmarshaler.
func (s *Ints[D]) UnmarshalCSV(data []byte) error {
	if len(data) == 0 {
		*s = nil
		return nil
	}
	var delimiter D
	parts := strings.Split(string(data), delimiter.Separator())
	if delimiter.Separator() == (Space{}).Separator() {
		parts = strings.Fields(string(data))
	}
	values := make(Ints[D], len(parts))
	for i, part := range parts {
		value, err := strconv.ParseInt(strings.TrimSpace(part), 10, 64)
		if err != nil {
			return fmt.Errorf("csvx.Ints: parse %q: %w", part, err)
		}
		values[i] = value
	}
	*s = values
	return nil
}
