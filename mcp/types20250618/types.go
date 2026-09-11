// Package mcptypes defines the types for the Model Context Protocol (JSON-RPC 2.0).
//
// This is a minimal, self-contained implementation covering the subset of the
// MCP spec we use: tools, resources, and the MCP Apps extension. Originally
// derived from mcp-go (github.com/mark3labs/mcp-go) then simplified to struct
// literals, typed schemas, and no builder patterns.
package mcptypes

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"maps"
)

// ---------------------------------------------------------------------------
// JSON-RPC 2.0
// ---------------------------------------------------------------------------

// JSONRPCVersion is the JSON-RPC protocol version.
const JSONRPCVersion = "2.0"

// IDish is a JSON-RPC request ID. Its zero value is null.
//
// JSON-RPC permits string, number, and null IDs. json.Number preserves the
// original numeric spelling and avoids losing precision through float64.
type IDish struct {
	value any // string | json.Number | nil
}

// NewInt creates an integer ID.
func NewInt(value int64) IDish {
	return IDish{value: json.Number(fmt.Sprintf("%d", value))}
}

// NewFloat creates a floating-point ID.
func NewFloat(value float64) IDish {
	return IDish{value: json.Number(fmt.Sprintf("%g", value))}
}

// NewString creates a string ID.
func NewString(value string) IDish {
	return IDish{value: value}
}

// NewNull creates a null ID. The zero value is equivalent.
func NewNull() IDish { return IDish{} }

func (id IDish) MarshalJSON() ([]byte, error) {
	if id.value == nil {
		return []byte("null"), nil
	}
	return json.Marshal(id.value)
}

func (id *IDish) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("invalid JSON-RPC id: %s", data)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("invalid JSON-RPC id: %s", data)
	}
	switch value := value.(type) {
	case nil, string, json.Number:
		id.value = value
		return nil
	default:
		return fmt.Errorf("JSON-RPC id must be a string, number, or null: %s", data)
	}
}

func (id IDish) String() string {
	switch value := id.value.(type) {
	case string:
		return value
	case json.Number:
		return value.String()
	default:
		return "null"
	}
}

// MarshalText encodes the ID as text. Null is encoded as "null".
func (id IDish) MarshalText() ([]byte, error) {
	return []byte(id.String()), nil
}

// MarshalCSV encodes null as an empty field and other IDs as their text form.
func (id IDish) MarshalCSV() (string, error) {
	text, err := id.MarshalText()
	if id.value == nil {
		return "", err
	}
	return string(text), err
}

// IsNull reports whether the ID explicitly contains JSON null.
func (id IDish) IsNull() bool {
	return id.value == nil
}

// RequestID is retained as an alias for callers using the original name.
type RequestID = IDish

// JSONRPCRequest is an incoming JSON-RPC 2.0 request.
type JSONRPCRequest struct {
	JSONRPC   string          `json:"jsonrpc"`
	ID        *RequestID      `json:"id,omitempty"` // nil for notifications
	IDPresent bool            `json:"-"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params,omitempty"`
	Meta      map[string]any  `json:"_meta,omitempty"`
}

// UnmarshalJSON records whether the request contained an ID. JSON null and an
// absent ID both decode to nil pointers, but only the latter is a notification.
func (r *JSONRPCRequest) UnmarshalJSON(data []byte) error {
	type request JSONRPCRequest
	var decoded request
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*r = JSONRPCRequest(decoded)
	_, r.IDPresent = fields["id"]
	return nil
}

// IsNotification returns true if this is a JSON-RPC notification (no id).
func (r *JSONRPCRequest) IsNotification() bool {
	return !r.IDPresent
}

// JSONRPCResponse is a successful JSON-RPC 2.0 response.
type JSONRPCResponse struct {
	JSONRPC string     `json:"jsonrpc"`
	ID      *RequestID `json:"id"`
	Result  any        `json:"result"`
}

// JSONRPCError is a JSON-RPC 2.0 error response.
type JSONRPCError struct {
	JSONRPC string              `json:"jsonrpc"`
	ID      *RequestID          `json:"id"`
	Error   JSONRPCErrorDetails `json:"error"`
}

// JSONRPCErrorDetails contains the error code, message, and optional data.
type JSONRPCErrorDetails struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
	Data    any    `json:"data,omitempty"`
}

// Standard JSON-RPC error codes.
const (
	ErrCodeParse            = -32700
	ErrCodeInvalidRequest   = -32600
	ErrCodeMethodNotFound   = -32601
	ErrCodeInvalidParams    = -32602
	ErrCodeInternal         = -32603
	ErrCodeResourceNotFound = -32002
)

// PaginatedRequest contains the optional opaque cursor used by list methods.
type PaginatedRequest struct {
	Cursor string `json:"cursor,omitempty"`
}

// JSONRPCNotification is an outbound notification (no id).
type JSONRPCNotification struct {
	JSONRPC string `json:"jsonrpc"`
	Method  string `json:"method"`
	Params  any    `json:"params,omitempty"`
}

// ---------------------------------------------------------------------------
// Initialize response
// ---------------------------------------------------------------------------

// InitializeResult is the typed response for the "initialize" method.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
	Instructions    string             `json:"instructions,omitempty"`
}

// InitializeParams contains the client's version, capabilities, and identity.
type InitializeParams struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ClientCapabilities `json:"capabilities"`
	ClientInfo      ClientInfo         `json:"clientInfo"`
}

// ClientCapabilities describes optional features offered by a client.
type ClientCapabilities struct {
	Experimental map[string]map[string]any `json:"experimental,omitempty"`
	Roots        *RootsCapability          `json:"roots,omitempty"`
	Sampling     map[string]any            `json:"sampling,omitempty"`
	Elicitation  map[string]any            `json:"elicitation,omitempty"`
}

type RootsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ServerCapabilities describes optional features offered by a server.
type ServerCapabilities struct {
	Experimental map[string]map[string]any `json:"experimental,omitempty"`
	Logging      map[string]any            `json:"logging,omitempty"`
	Completions  map[string]any            `json:"completions,omitempty"`
	Prompts      *PromptsCapability        `json:"prompts,omitempty"`
	Resources    *ResourcesCapability      `json:"resources,omitempty"`
	Tools        *ToolsCapability          `json:"tools,omitempty"`
}

type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ClientInfo identifies the client implementation.
type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerInfo identifies the server implementation.
type ServerInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}

// ---------------------------------------------------------------------------
// Meta
// ---------------------------------------------------------------------------

// AppUI is the _meta.ui object shared by tools and resources in the MCP Apps spec.
// Tools set ResourceURI and Visibility; resources set CSP and Permissions.
// All fields are optional; omitempty keeps the wire format clean.
// See https://github.com/modelcontextprotocol/ext-apps/blob/main/specification/draft/apps.mdx
type AppUI struct {
	// Tool fields
	ResourceURI string   `json:"resourceUri,omitempty"`
	Visibility  []string `json:"visibility,omitempty"`

	// Resource fields
	CSP         *AppCSP         `json:"csp,omitempty"`
	Permissions *AppPermissions `json:"permissions,omitempty"`
}

// AppCSP controls which external origins the sandboxed app can load from.
type AppCSP struct {
	ConnectDomains  []string `json:"connectDomains,omitempty"`
	ResourceDomains []string `json:"resourceDomains,omitempty"`
	FrameDomains    []string `json:"frameDomains,omitempty"`
	BaseURIDomains  []string `json:"baseUriDomains,omitempty"`
}

// AppPermissions declares iframe sandbox permissions as empty-object markers.
type AppPermissions struct {
	ClipboardWrite *struct{} `json:"clipboardWrite,omitempty"`
	Camera         *struct{} `json:"camera,omitempty"`
	Microphone     *struct{} `json:"microphone,omitempty"`
	Geolocation    *struct{} `json:"geolocation,omitempty"`
}

// Meta carries additional metadata on tools, resources, and results.
// Values holds non-MCP extension fields; UI is the typed MCP Apps field.
type Meta struct {
	Values map[string]any `json:"-"`
	UI     *AppUI         `json:"-"`
}

// MarshalJSON preserves arbitrary extension metadata while encoding the typed
// MCP Apps field under its reserved "ui" key.
func (m Meta) MarshalJSON() ([]byte, error) {
	values := make(map[string]any, len(m.Values)+1)
	maps.Copy(values, m.Values)
	if m.UI != nil {
		values["ui"] = m.UI
	}
	return json.Marshal(values)
}

// UnmarshalJSON decodes arbitrary metadata and the typed MCP Apps field.
func (m *Meta) UnmarshalJSON(data []byte) error {
	var values map[string]any
	if err := json.Unmarshal(data, &values); err != nil {
		return err
	}
	delete(values, "ui")
	m.Values = values
	var raw struct {
		UI *AppUI `json:"ui"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return err
	}
	m.UI = raw.UI
	return nil
}

// IsEmpty returns true when Meta carries no data. Used by containers that
// need to decide whether to omit the _meta key entirely.
func (m *Meta) IsEmpty() bool {
	return m == nil || (m.UI == nil && len(m.Values) == 0)
}

// ---------------------------------------------------------------------------
// Content types
// ---------------------------------------------------------------------------

// Content is a union type for tool result content.
// mcp-go uses separate TextContent, ImageContent, AudioContent structs each with
// an Annotated embed and Meta field. We use a single flat struct since we only
// produce text content; add typed variants when image/audio support is needed.
type Content struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MIMEType string `json:"mimeType,omitempty"`
}

// TextContent represents text content in a tool result.
type TextContent = Content
