package mcptypes

import (
	"encoding/json"
	"fmt"
)

// ---------------------------------------------------------------------------
// Tool definition
// ---------------------------------------------------------------------------

// Tool describes an MCP tool with its name, description, input schema, and hints.
//
// Differences from mcp-go:
//   - Annotations is a pointer (omitted when nil); mcp-go uses a value (always serialized).
//   - Omits: RawInputSchema, OutputSchema, RawOutputSchema, DeferLoading, Icons, Execution.
//     These are unused; add them when needed.
//
// We intentionally reject complex runtime schema validation here. The schema
// is typed instead, and handlers validate and decode their arguments using Go
// types and the accessors on CallToolRequest.
type Tool struct {
	Meta        *Meta           `json:"_meta,omitempty"`
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	InputSchema ToolInputSchema `json:"inputSchema"`
	Annotations *ToolAnnotation `json:"annotations,omitempty"`
}

// Property describes a single property in a tool's input schema.
type Property struct {
	Type        string           `json:"type"`
	Description string           `json:"description,omitempty"`
	Enum        []string         `json:"enum,omitempty"`
	Default     string           `json:"default,omitempty"`
	Items       *ToolInputSchema `json:"items,omitempty"`
}

// ToolInputSchema is the JSON Schema advertised for tool input. It covers the
// simple typed schemas supported by this package; handlers enforce semantics.
type ToolInputSchema struct {
	Type       string              `json:"type"`
	Properties map[string]Property `json:"properties,omitempty"`
	Required   []string            `json:"required,omitempty"`
}

// ToolAnnotation contains behavioral hints for clients.
type ToolAnnotation struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}

// ---------------------------------------------------------------------------
// Tool call request
// ---------------------------------------------------------------------------

// CallToolRequest is the request object passed to tool handlers.
type CallToolRequest struct {
	Method string
	Params CallToolParams
}

// CallToolParams contains the tool call parameters.
type CallToolParams struct {
	Name      string         `json:"name"`
	Arguments map[string]any `json:"arguments,omitempty"`
}

// GetArguments returns the raw arguments map.
func (r CallToolRequest) GetArguments() map[string]any {
	return r.Params.Arguments
}

// GetString returns a string argument or the default value.
func (r CallToolRequest) GetString(key, defaultValue string) string {
	v, ok := r.Params.Arguments[key]
	if !ok {
		return defaultValue
	}
	s, ok := v.(string)
	if !ok {
		return defaultValue
	}
	return s
}

// GetInt returns an integer argument or the default value.
func (r CallToolRequest) GetInt(key string, defaultValue int) int {
	v, ok := r.Params.Arguments[key]
	if !ok {
		return defaultValue
	}
	switch n := v.(type) {
	case float64:
		return int(n)
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return defaultValue
		}
		return int(i)
	case int:
		return n
	case int64:
		return int(n)
	default:
		return defaultValue
	}
}

// GetFloat returns a float argument or the default value.
func (r CallToolRequest) GetFloat(key string, defaultValue float64) float64 {
	v, ok := r.Params.Arguments[key]
	if !ok {
		return defaultValue
	}
	switch n := v.(type) {
	case float64:
		return n
	case json.Number:
		f, err := n.Float64()
		if err != nil {
			return defaultValue
		}
		return f
	default:
		return defaultValue
	}
}

// GetBool returns a boolean argument or the default value.
func (r CallToolRequest) GetBool(key string, defaultValue bool) bool {
	v, ok := r.Params.Arguments[key]
	if !ok {
		return defaultValue
	}
	b, ok := v.(bool)
	if !ok {
		return defaultValue
	}
	return b
}

// RequireString returns the string argument or an error if missing.
func (r CallToolRequest) RequireString(key string) (string, error) {
	v, ok := r.Params.Arguments[key]
	if !ok {
		return "", fmt.Errorf("missing required argument: %s", key)
	}
	s, ok := v.(string)
	if !ok {
		return "", fmt.Errorf("argument %s must be a string", key)
	}
	return s, nil
}

// RequireInt returns the integer argument or an error if missing.
func (r CallToolRequest) RequireInt(key string) (int, error) {
	v, ok := r.Params.Arguments[key]
	if !ok {
		return 0, fmt.Errorf("missing required argument: %s", key)
	}
	switch n := v.(type) {
	case float64:
		return int(n), nil
	case json.Number:
		i, err := n.Int64()
		if err != nil {
			return 0, fmt.Errorf("argument %s must be an integer", key)
		}
		return int(i), nil
	default:
		return 0, fmt.Errorf("argument %s must be a number", key)
	}
}

// BindArguments unmarshals arguments into the target struct.
func (r CallToolRequest) BindArguments(target any) error {
	data, err := json.Marshal(r.Params.Arguments)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, target)
}

// ---------------------------------------------------------------------------
// Tool call result
// ---------------------------------------------------------------------------

// CallToolResult is the response from a tool handler.
type CallToolResult struct {
	Meta              *Meta     `json:"-"` // marshaled manually; see MarshalJSON
	Content           []Content `json:"-"`
	StructuredContent any       `json:"-"`
	IsError           bool      `json:"-"`
}

// MarshalJSON writes only non-empty fields and omits _meta when it carries no
// data — matching the wire format produced by mcp-go.
func (r CallToolResult) MarshalJSON() ([]byte, error) {
	m := make(map[string]any, 4)
	if r.Meta != nil && !r.Meta.IsEmpty() {
		m["_meta"] = r.Meta
	}
	m["content"] = r.Content
	if r.StructuredContent != nil {
		m["structuredContent"] = r.StructuredContent
	}
	if r.IsError {
		m["isError"] = r.IsError
	}
	return json.Marshal(m)
}

// NewToolResultText creates a result with a single text content.
func NewToolResultText(text string) *CallToolResult {
	return &CallToolResult{
		Content: []Content{TextContent{Type: "text", Text: text}},
	}
}

// NewToolResultError creates an error result with text content.
func NewToolResultError(message string) *CallToolResult {
	return &CallToolResult{
		Content: []Content{TextContent{Type: "text", Text: message}},
		IsError: true,
	}
}

// NewToolResultJSON creates a result with JSON-serialized structured content and text.
func NewToolResultJSON(data any) (*CallToolResult, error) {
	textBytes, err := json.Marshal(data)
	if err != nil {
		return nil, err
	}
	return &CallToolResult{
		Content:           []Content{TextContent{Type: "text", Text: string(textBytes)}},
		StructuredContent: data,
	}, nil
}

// NewToolResultStructured creates a result with both structured and text content.
func NewToolResultStructured(structured any, text string) *CallToolResult {
	return &CallToolResult{
		Content:           []Content{TextContent{Type: "text", Text: text}},
		StructuredContent: structured,
	}
}

// NewToolResultStructuredOnly creates a result with structured content and a
// JSON text fallback for backward compatibility with clients that don't
// support structuredContent.
func NewToolResultStructuredOnly(structured any) *CallToolResult {
	var fallbackText string
	jsonBytes, err := json.Marshal(structured)
	if err != nil {
		fallbackText = fmt.Sprintf("Error serializing structured content: %v", err)
	} else {
		fallbackText = string(jsonBytes)
	}
	return &CallToolResult{
		Content:           []Content{TextContent{Type: "text", Text: fallbackText}},
		StructuredContent: structured,
	}
}
