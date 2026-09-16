package csvx

import (
	"strings"
	"unicode"
)

// Listish is a list encoded as comma- or whitespace-delimited text.
type Listish []string

// UnmarshalCSV parses comma- or whitespace-delimited values.
func (s *Listish) UnmarshalCSV(data []byte) error {
	if len(data) == 0 {
		*s = Listish{}
		return nil
	}
	parts := strings.FieldsFunc(string(data), func(r rune) bool {
		return r == ',' || unicode.IsSpace(r)
	})
	if len(parts) == 0 {
		*s = Listish{}
		return nil
	}
	*s = Listish(parts)
	return nil
}
