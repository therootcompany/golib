package xhubsig

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

type httpError struct {
	Error       string `json:"error"`
	Description string `json:"description,omitempty"`
	Hint        string `json:"hint,omitempty"`
}

func (e httpError) rows() [][2]string {
	rows := [][2]string{{"error", e.Error}}
	if e.Description != "" {
		rows = append(rows, [2]string{"description", e.Description})
	}
	if e.Hint != "" {
		rows = append(rows, [2]string{"hint", e.Hint})
	}
	return rows
}

func acceptedFormat(accept string) string {
	for part := range strings.SplitSeq(accept, ",") {
		mt := strings.TrimSpace(strings.SplitN(part, ";", 2)[0])
		switch mt {
		case "application/json":
			return "json"
		case "text/csv":
			return "csv"
		case "text/markdown":
			return "markdown"
		case "text/html":
			return "text/plain"
		}
	}
	return "tsv"
}

// writeDelimited writes vertical key-value TSV or CSV. Newlines within
// values are collapsed to a space so agents can split on newlines reliably.
func writeDelimited(w http.ResponseWriter, httpCode int, ct string, sep rune, e httpError) {
	w.Header().Set("Content-Type", ct)
	w.WriteHeader(httpCode)
	cw := csv.NewWriter(w)
	cw.Comma = sep
	cw.Write([]string{"field", "value"})
	for _, row := range e.rows() {
		cw.Write([]string{row[0], strings.ReplaceAll(row[1], "\n", " ")})
	}
	cw.Flush()
}

func serializeError(w http.ResponseWriter, r *http.Request, httpCode int, e httpError) {
	switch acceptedFormat(r.Header.Get("Accept")) {
	case "tsv":
		writeDelimited(w, httpCode, "text/tab-separated-values", '\t', e)
	case "text/plain":
		writeDelimited(w, httpCode, "text/plain", '\t', e)
	case "csv":
		writeDelimited(w, httpCode, "text/csv", ',', e)
	case "markdown":
		w.Header().Set("Content-Type", "text/markdown")
		w.WriteHeader(httpCode)
		fmt.Fprintln(w, "| field | value |")
		fmt.Fprintln(w, "| --- | --- |")
		for _, row := range e.rows() {
			fmt.Fprintf(w, "| %s | %s |\n", row[0], strings.ReplaceAll(row[1], "\n", " "))
		}
	default:
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(httpCode)
		json.NewEncoder(w).Encode(e)
	}
}
