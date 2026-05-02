package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// isTTYish reports whether f is a terminal (character device).
func isTTYish(f *os.File) bool {
	fi, err := f.Stat()
	if err != nil {
		return false
	}
	m := os.ModeDevice | os.ModeCharDevice
	return fi.Mode()&m == m
}

// writeTable renders results in the chosen format to stdout.
func writeTable(format string, results []result) error {
	switch format {
	case formatPretty:
		w := 0
		for _, r := range results {
			if len(r.IP) > w {
				w = len(r.IP)
			}
		}
		for _, r := range results {
			fmt.Printf("%-*s  %s\n", w, r.IP, statusLabel(r.Found))
		}
	case formatTSV:
		for _, r := range results {
			fmt.Printf("%s\t%s\n", r.IP, statusLabel(r.Found))
		}
	case formatCSV:
		cw := csv.NewWriter(os.Stdout)
		_ = cw.Write([]string{"ip", "status"})
		for _, r := range results {
			if err := cw.Write([]string{r.IP, statusLabel(r.Found)}); err != nil {
				return err
			}
		}
		cw.Flush()
		return cw.Error()
	case formatJSON:
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(results)
	}
	return nil
}

func statusLabel(found bool) string {
	if found {
		return "FOUND"
	}
	return "NOT FOUND"
}

// commafy renders n with thousands separators, e.g. 1234567 -> "1,234,567".
func commafy(n int) string {
	s := strconv.Itoa(n)
	neg := ""
	if n < 0 {
		neg, s = "-", s[1:]
	}
	if len(s) <= 3 {
		return neg + s
	}
	var b strings.Builder
	head := len(s) % 3
	if head > 0 {
		b.WriteString(s[:head])
		b.WriteByte(',')
	}
	for i := head; i < len(s); i += 3 {
		b.WriteString(s[i : i+3])
		if i+3 < len(s) {
			b.WriteByte(',')
		}
	}
	return neg + b.String()
}
