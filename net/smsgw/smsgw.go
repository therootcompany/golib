package smsgw

import (
	"fmt"
	"strings"
)

var ErrInvalidClockFormat = fmt.Errorf("invalid clock time, ex: '06:00 PM', '6pm', or '18:00' (space and case insensitive)")
var ErrInvalidClockTime = fmt.Errorf("invalid hour or minute, for example '27:63 p' would not be valid")
var ErrPhoneEmpty = fmt.Errorf("no phone number")
var ErrPhoneInvalid11 = fmt.Errorf("invalid 11-digit number (does not start with 1)")
var ErrPhoneInvalid12 = fmt.Errorf("invalid 12-digit number (does not start with +1)")
var ErrPhoneInvalidLength = fmt.Errorf("invalid number length (should be 10 digits or 12 with +1 prefix)")

type Gateway interface {
	CurlString(to, text string) string
	Send(to, text string) error
}

// Strips away symbols, non-printing characters copied from HTML, etc,
// leaving only a possible leading '+' and digits.
// Does not leave *, # or comma.
func StripFormatting(raw string) string {
	var cleaned strings.Builder
	for i, char := range raw {
		if (i == 0 && char == '+') || (char >= '0' && char <= '9') {
			cleaned.WriteRune(char)
		}
	}
	return cleaned.String()
}

// Adds +1 to a 10-digit, or ? to an 11-digit with a leading 1, or leaves a 12-digit with leading +1 as-is
func PrefixUS10Digit(number string) (string, error) {
	switch len(number) {
	case 0:
		return "", ErrPhoneEmpty
	case 10:
		return "+1" + number, nil
	case 11:
		if strings.HasPrefix(number, "1") {
			return "+" + number, nil
		}
		return "", fmt.Errorf("%w: %s", ErrPhoneInvalid11, number)
	case 12:
		if strings.HasPrefix(number, "+1") {
			return number, nil
		}
		return "", fmt.Errorf("%w: %s", ErrPhoneInvalid12, number)
	default:
		return "", fmt.Errorf("%w: %s", ErrPhoneInvalidLength, number)
	}
}
