// Package jsontypes infers type structure from JSON samples and generates
// type definitions in multiple output formats.
//
// Given a JSON value (object, array, or primitive), jsontypes walks the
// structure depth-first, detects maps vs structs, infers optional fields
// from multiple instances, and produces a flat path notation called
// "json-paths" that captures the full type tree:
//
//	{Root}
//	.users[]{User}
//	.users[].id{int}
//	.users[].name{string}
//	.users[].email{string?}
//
// These paths can then be rendered into typed definitions for any target:
//
//   - [GenerateGoStructs]: Go struct definitions with json tags
//   - [GenerateTypeScript]: TypeScript interfaces
//   - [GenerateJSDoc]: JSDoc @typedef annotations
//   - [GenerateZod]: Zod validation schemas
//   - [GeneratePython]: Python TypedDict classes
//   - [GenerateSQL]: SQL CREATE TABLE with foreign key relationships
//   - [GenerateJSONSchema]: JSON Schema (draft 2020-12)
//   - [GenerateTypedef]: JSON Typedef (RFC 8927)
//
// # Quick start
//
// For non-interactive use (e.g., from an AI agent or script):
//
//	import "encoding/json"
//	import "github.com/therootcompany/golib/tools/jsontypes"
//
//	var data any
//	dec := json.NewDecoder(input)
//	dec.UseNumber()
//	dec.Decode(&data)
//
//	a, _ := jsontypes.NewAnalyzer(false, true, false) // anonymous mode
//	defer a.Close()
//
//	paths := jsontypes.FormatPaths(a.Analyze(".", data))
//	fmt.Print(jsontypes.GenerateTypeScript(paths))
//
// # AI tool use
//
// This package is designed to be callable as an AI skill. Given a JSON
// API response, an agent can infer the complete type structure and emit
// ready-to-use type definitions — no schema file required. The json-paths
// intermediate format is both human-readable and machine-parseable,
// making it suitable for tool-use chains where an agent needs to
// understand an API's shape before generating code.
package jsontypes
