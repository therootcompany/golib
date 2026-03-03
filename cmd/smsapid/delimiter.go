package main

import "unicode/utf8"

const (
	fileSeparator   = '\x1c'
	groupSeparator  = '\x1d'
	recordSeparator = '\x1e'
	unitSeparator   = '\x1f'
)

func DecodeDelimiter(delimString string) (rune, error) {
	switch delimString {
	case "^_", "\\x1f":
		delimString = string(unitSeparator)
	case "^^", "\\x1e":
		delimString = string(recordSeparator)
	case "^]", "\\x1d":
		delimString = string(groupSeparator)
	case "^\\", "\\x1c":
		delimString = string(fileSeparator)
	case "^L", "\\f":
		delimString = "\f"
	case "^K", "\\v":
		delimString = "\v"
	case "^I", "\\t":
		delimString = "\t"
	default:
		// it is what it is
	}
	delim, _ := utf8.DecodeRuneInString(delimString)
	return delim, nil
}
