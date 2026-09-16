package csvx

import (
	"encoding/hex"
	"strconv"
	"strings"

	"github.com/jszwec/csvutil"
)

// Marshalers returns csvutil.Marshalers for generic types that don't have
// their own MarshalCSV method.
func Marshalers() *csvutil.Marshalers {
	return csvutil.NewMarshalers(
		csvutil.MarshalFunc[[]string](func(s []string) ([]byte, error) {
			if len(s) == 0 {
				return nil, nil
			}
			return []byte(strings.Join(s, ",")), nil
		}),
		csvutil.MarshalFunc[*bool](func(b *bool) ([]byte, error) {
			if b == nil {
				return nil, nil
			}
			return []byte(strconv.FormatBool(*b)), nil
		}),
		csvutil.MarshalFunc[[]byte](func(b []byte) ([]byte, error) {
			if len(b) == 0 {
				return nil, nil
			}
			return []byte(hex.EncodeToString(b)), nil
		}),
	)
}

// Unmarshalers returns csvutil.Unmarshalers for generic types that don't have
// their own UnmarshalCSV method.
func Unmarshalers() *csvutil.Unmarshalers {
	return csvutil.NewUnmarshalers(
		csvutil.UnmarshalFunc[*[]string](func(data []byte, s *[]string) error {
			str := string(data)
			if str == "" {
				*s = nil
				return nil
			}
			*s = strings.Split(str, ",")
			return nil
		}),
		csvutil.UnmarshalFunc[*bool](func(data []byte, b *bool) error {
			s := string(data)
			if s == "" {
				*b = false
				return nil
			}
			v, err := strconv.ParseBool(strings.TrimSpace(s))
			if err != nil {
				return err
			}
			*b = v
			return nil
		}),
		csvutil.UnmarshalFunc[*[]byte](func(data []byte, b *[]byte) error {
			s := string(data)
			if s == "" {
				*b = nil
				return nil
			}
			decoded, err := hex.DecodeString(s)
			if err != nil {
				return err
			}
			*b = decoded
			return nil
		}),
	)
}
