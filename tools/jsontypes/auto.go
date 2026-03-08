package jsontypes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// Format identifies a target output format for type generation.
type Format string

const (
	FormatGo         Format = "go"
	FormatTypeScript Format = "typescript"
	FormatJSDoc      Format = "jsdoc"
	FormatZod        Format = "zod"
	FormatPython     Format = "python"
	FormatSQL        Format = "sql"
	FormatJSONSchema Format = "jsonschema"
	FormatTypedef    Format = "typedef"
	FormatFlatPaths  Format = "paths"
)

// Options configures AutoGenerate behavior.
type Options struct {
	// Format selects the output format (default: FormatFlatPaths).
	Format Format

	// Resolver handles interactive decisions during analysis.
	// If nil, heuristic defaults are used (fully autonomous).
	Resolver Resolver

	// AskTypes prompts for every type name, even when heuristics
	// are confident. Only meaningful when Resolver is set.
	AskTypes bool
}

// ParseFormat normalizes a format string, accepting common aliases.
// Returns an error for unrecognized formats.
func ParseFormat(s string) (Format, error) {
	if f, ok := formatAliases[s]; ok {
		return f, nil
	}
	return "", fmt.Errorf("unknown format: %q (use: paths, go, typescript, jsdoc, zod, python, sql, jsonschema, typedef)", s)
}

var formatAliases = map[string]Format{
	"":              FormatFlatPaths,
	"paths":         FormatFlatPaths,
	"json-paths":    FormatFlatPaths,
	"go":            FormatGo,
	"typescript":    FormatTypeScript,
	"ts":            FormatTypeScript,
	"jsdoc":         FormatJSDoc,
	"zod":           FormatZod,
	"python":        FormatPython,
	"py":            FormatPython,
	"sql":           FormatSQL,
	"jsonschema":    FormatJSONSchema,
	"json-schema":   FormatJSONSchema,
	"typedef":       FormatTypedef,
	"json-typedef":  FormatTypedef,
}

// Generate renders formatted paths into the given output format.
// Use FormatFlatPaths to get the intermediate path notation.
func Generate(format Format, paths []string) (string, error) {
	if format == FormatFlatPaths {
		return strings.Join(paths, "\n") + "\n", nil
	}
	gen, ok := generators[format]
	if !ok {
		return "", fmt.Errorf("unknown format: %q", format)
	}
	return gen(paths), nil
}

// AutoGenerate parses JSON from raw bytes and generates type definitions.
func AutoGenerate(data []byte, opts Options) (string, error) {
	var v any
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&v); err != nil {
		return "", fmt.Errorf("invalid JSON: %w", err)
	}
	return AutoGenerateFromAny(v, opts)
}

// AutoGenerateFromString parses a JSON string and generates type definitions.
func AutoGenerateFromString(s string, opts Options) (string, error) {
	return AutoGenerate([]byte(s), opts)
}

// AutoGenerateFromAny generates type definitions from an already-decoded JSON
// value. The value must have been decoded with json.UseNumber() so that
// integers and floats are distinguishable.
func AutoGenerateFromAny(v any, opts Options) (string, error) {
	a := New(AnalyzerConfig{Resolver: opts.Resolver, AskTypes: opts.AskTypes})
	paths := FormatPaths(a.Analyze(".", v))
	format := opts.Format
	if format == "" {
		format = FormatFlatPaths
	}
	return Generate(format, paths)
}

var generators = map[Format]func([]string) string{
	FormatGo:         GenerateGoStructs,
	FormatTypeScript: GenerateTypeScript,
	FormatJSDoc:      GenerateJSDoc,
	FormatZod:        GenerateZod,
	FormatPython:     GeneratePython,
	FormatSQL:        GenerateSQL,
	FormatJSONSchema: GenerateJSONSchema,
	FormatTypedef:    GenerateTypedef,
}
