package main

import (
	"fmt"
	"os"
)

const (
	formatPretty = "pretty"
	formatTSV    = "tsv"
	formatCSV    = "csv"
	formatJSON   = "json"
)

// parseFormat resolves the --format flag value, auto-detecting based on
// stdout (pretty on TTY, tsv when piped) when s is empty.
func parseFormat(s string) (string, error) {
	switch s {
	case "":
		if isTTYish(os.Stdout) {
			return formatPretty, nil
		}
		return formatTSV, nil
	case formatPretty, formatTSV, formatCSV, formatJSON:
		return s, nil
	default:
		return "", fmt.Errorf("unknown format %q (want pretty, tsv, csv, json)", s)
	}
}

type result struct {
	IP    string `json:"ip"`
	Found bool   `json:"found"`
}
