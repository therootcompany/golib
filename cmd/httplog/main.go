package main

import (
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/therootcompany/golib/colorjson"
)

var jsonf = colorjson.NewFormatter()

func main() {
	jsonf.Indent = 3
	color.NoColor = false // TODO manual override via flags

	mux := http.NewServeMux()
	mux.HandleFunc("GET /", handler)
	mux.HandleFunc("POST /", handler)
	mux.HandleFunc("PATCH /", handler)
	mux.HandleFunc("PUT /", handler)
	mux.HandleFunc("DELETE /", handler)

	addr := "localhost:8088"
	fmt.Printf("Listening on %s...\n\n", addr)
	log.Fatal(http.ListenAndServe(addr, mux))
}

func handler(w http.ResponseWriter, r *http.Request) {
	// Log method, path, and query
	var query string
	if len(r.URL.RawQuery) > 0 {
		query = "?" + r.URL.RawQuery
	}
	log.Printf("%s %s%s", r.Method, r.URL.Path, query)

	// Find max header name length for alignment
	maxLen := len("HOST")
	for name := range r.Header {
		if len(name) > maxLen {
			maxLen = len(name)
		}
	}
	maxLen += 1

	fmt.Printf("   %-"+fmt.Sprintf("%d", maxLen+1)+"s %s\n", "HOST", r.Host)
	for name, values := range r.Header {
		for _, value := range values {
			fmt.Printf("   %-"+fmt.Sprintf("%d", maxLen+1)+"s %s\n", name+":", value)
		}
	}
	fmt.Fprintf(os.Stderr, "\n")

	body, err := io.ReadAll(r.Body)
	switch strings.ToUpper(r.Method) {
	case "GET", "DELETE":
		if len(body) > 0 {
			fmt.Fprintf(os.Stderr, "Unexpected body:\n%q\n", string(body))
		}
		return
	case "POST", "PATCH", "PUT":
		break
	default:
		fmt.Fprintf(os.Stderr, "Unexpected method\n")
		return
	}
	defer fmt.Println()

	// Read request body
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read body:\n%q\n", string(body))
		return
	}
	defer func() {
		_ = r.Body.Close()
	}()

	// Parse and pretty-print JSON, or raw body
	var text string
	var data any
	if err := json.Unmarshal(body, &data); err == nil {
		body, _ = jsonf.Marshal(data)
	}

	text = string(body)
	text = prefixLines(text, "   ")
	text = strings.TrimSpace(text)
	fmt.Printf("   %s\n", text)
}

func prefixLines(text, prefix string) string {
	lines := strings.Split(text, "\n")
	for i, line := range lines {
		lines[i] = prefix + line
	}
	return strings.Join(lines, "\n")
}
