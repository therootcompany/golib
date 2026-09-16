package csvx

import (
	"database/sql/driver"
	"encoding/json"
	"fmt"
	"strings"
)

// Textish is text with common explicit-empty words normalized to an empty value.
type Textish string

func (t Textish) Empty() bool { return string(t) == "" }

func (t Textish) String() string { return string(t) }

func normalizeTextish(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "", "none", "disable", "disabled":
		return ""
	default:
		return strings.TrimSpace(value)
	}
}

func (t Textish) Value() (driver.Value, error) { return string(t), nil }

func (t *Textish) Scan(value any) error {
	if value == nil {
		*t = ""
		return nil
	}
	switch v := value.(type) {
	case string:
		*t = Textish(normalizeTextish(v))
	case []byte:
		*t = Textish(normalizeTextish(string(v)))
	default:
		return fmt.Errorf("csvx.Textish: cannot scan %T", value)
	}
	return nil
}

func (t Textish) MarshalCSV() ([]byte, error) { return []byte(t), nil }

func (t *Textish) UnmarshalCSV(data []byte) error {
	*t = Textish(normalizeTextish(string(data)))
	return nil
}

func (t Textish) MarshalJSON() ([]byte, error) { return json.Marshal(string(t)) }

func (t *Textish) UnmarshalJSON(data []byte) error {
	var value string
	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}
	*t = Textish(normalizeTextish(value))
	return nil
}
