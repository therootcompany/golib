// Package mcptypes defines the typed MCP 2026-07-28 wire model.
//
// Core protocol values use Go structs. json.RawMessage is used only where the
// specification deliberately permits arbitrary JSON (extensions, JSON Schema,
// and structured tool content).
package mcptypes

import (
	"bytes"
	"encoding/json"
	"fmt"
)

const (
	JSONRPCVersion  = "2.0"
	ProtocolVersion = "2026-07-28"
)

type RequestID struct{ value json.RawMessage }

func NewStringID(value string) RequestID {
	return RequestID{value: json.RawMessage(fmt.Sprintf("%q", value))}
}
func NewNumberID(value json.Number) RequestID {
	return RequestID{value: json.RawMessage(value.String())}
}
func (id RequestID) IsNull() bool { return len(id.value) == 0 || bytes.Equal(id.value, []byte("null")) }
func (id RequestID) MarshalJSON() ([]byte, error) {
	if id.IsNull() {
		return []byte("null"), nil
	}
	return id.value, nil
}
func (id *RequestID) UnmarshalJSON(data []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	var value json.RawMessage
	if err := decoder.Decode(&value); err != nil {
		return fmt.Errorf("invalid JSON-RPC id: %w", err)
	}
	if len(value) == 0 {
		return fmt.Errorf("invalid JSON-RPC id")
	}
	switch value[0] {
	case '"', '-', '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
		id.value = append(id.value[:0], value...)
		return nil
	case 'n':
		if bytes.Equal(value, []byte("null")) {
			id.value = []byte("null")
			return nil
		}
	}
	return fmt.Errorf("JSON-RPC id must be a string, number, or null")
}

type Request struct {
	JSONRPC   string          `json:"jsonrpc"`
	ID        *RequestID      `json:"id,omitempty"`
	Method    string          `json:"method"`
	Params    json.RawMessage `json:"params,omitempty"`
	Meta      RequestMeta     `json:"_meta"`
	IDPresent bool            `json:"-"`
}

func (r *Request) UnmarshalJSON(data []byte) error {
	type alias Request
	var decoded alias
	if err := json.Unmarshal(data, &decoded); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return err
	}
	*r = Request(decoded)
	_, r.IDPresent = fields["id"]
	return nil
}
func (r Request) IsNotification() bool { return !r.IDPresent }

type RequestMeta struct {
	ProtocolVersion    string                     `json:"io.modelcontextprotocol/protocolVersion,omitempty"`
	ClientCapabilities ClientCapabilities         `json:"io.modelcontextprotocol/clientCapabilities"`
	ClientInfo         *ClientInfo                `json:"io.modelcontextprotocol/clientInfo,omitempty"`
	LogLevel           *LogLevel                  `json:"io.modelcontextprotocol/logLevel,omitempty"`
	Extensions         map[string]json.RawMessage `json:"-"`
}

type ResultMeta struct {
	ServerInfo     *ServerInfo                `json:"io.modelcontextprotocol/serverInfo,omitempty"`
	SubscriptionID string                     `json:"io.modelcontextprotocol/subscriptionId,omitempty"`
	Extensions     map[string]json.RawMessage `json:"-"`
}

type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      *RequestID      `json:"id"`
	Result  json.RawMessage `json:"result"`
}
type ErrorResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      *RequestID  `json:"id"`
	Error   ErrorObject `json:"error"`
}
type ErrorObject struct {
	Code    int             `json:"code"`
	Message string          `json:"message"`
	Data    json.RawMessage `json:"data,omitempty"`
}

const (
	ErrParse                           = -32700
	ErrInvalidRequest                  = -32600
	ErrMethodNotFound                  = -32601
	ErrInvalidParams                   = -32602
	ErrInternal                        = -32603
	ErrHeaderMismatch                  = -32020
	ErrMissingRequiredClientCapability = -32021
	ErrUnsupportedProtocolVersion      = -32022
)

type ClientInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}
type ServerInfo struct {
	Name    string `json:"name"`
	Title   string `json:"title,omitempty"`
	Version string `json:"version"`
}
type ClientCapabilities struct {
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
}
type ServerCapabilities struct {
	Extensions map[string]json.RawMessage `json:"extensions,omitempty"`
	Prompts    *PromptsCapability         `json:"prompts,omitempty"`
	Resources  *ResourcesCapability       `json:"resources,omitempty"`
	Tools      *ToolsCapability           `json:"tools,omitempty"`
}
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}
type ResourcesCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}
type LogLevel string

// Method parameter and result types.
type DiscoverParams struct{}
type DiscoverResult struct {
	ResultType       string             `json:"resultType"`
	ProtocolVersions []string           `json:"protocolVersions"`
	Capabilities     ServerCapabilities `json:"capabilities"`
	ServerInfo       ServerInfo         `json:"serverInfo"`
	Instructions     string             `json:"instructions,omitempty"`
	Meta             ResultMeta         `json:"_meta"`
}
type PaginatedParams struct {
	Cursor string `json:"cursor,omitempty"`
}
type ToolsListResult struct {
	ResultType string     `json:"resultType"`
	Tools      []Tool     `json:"tools"`
	NextCursor string     `json:"nextCursor,omitempty"`
	TTLMS      int64      `json:"ttlMs"`
	CacheScope CacheScope `json:"cacheScope"`
	Meta       ResultMeta `json:"_meta"`
}
type ResourcesListResult struct {
	ResultType string     `json:"resultType"`
	Resources  []Resource `json:"resources"`
	NextCursor string     `json:"nextCursor,omitempty"`
	TTLMS      int64      `json:"ttlMs"`
	CacheScope CacheScope `json:"cacheScope"`
	Meta       ResultMeta `json:"_meta"`
}
type ReadResourceParams struct {
	URI string `json:"uri"`
}
type ReadResourceResult struct {
	ResultType string             `json:"resultType"`
	Contents   []ResourceContents `json:"contents"`
	TTLMS      int64              `json:"ttlMs"`
	CacheScope CacheScope         `json:"cacheScope"`
	Meta       ResultMeta         `json:"_meta"`
}
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}
type CallToolResult struct {
	ResultType        string          `json:"resultType"`
	Content           []Content       `json:"content"`
	StructuredContent json.RawMessage `json:"structuredContent,omitempty"`
	IsError           bool            `json:"isError,omitempty"`
	Meta              ResultMeta      `json:"_meta"`
}
type CacheScope string

const (
	CachePublic  CacheScope = "public"
	CachePrivate CacheScope = "private"
)

type Tool struct {
	Meta         json.RawMessage  `json:"_meta,omitempty"`
	Name         string           `json:"name"`
	Title        string           `json:"title,omitempty"`
	Description  string           `json:"description,omitempty"`
	InputSchema  json.RawMessage  `json:"inputSchema"`
	OutputSchema json.RawMessage  `json:"outputSchema,omitempty"`
	Annotations  *ToolAnnotations `json:"annotations,omitempty"`
}
type ToolAnnotations struct {
	Title           string `json:"title,omitempty"`
	ReadOnlyHint    *bool  `json:"readOnlyHint,omitempty"`
	DestructiveHint *bool  `json:"destructiveHint,omitempty"`
	IdempotentHint  *bool  `json:"idempotentHint,omitempty"`
	OpenWorldHint   *bool  `json:"openWorldHint,omitempty"`
}
type Resource struct {
	Meta        json.RawMessage `json:"_meta,omitempty"`
	URI         string          `json:"uri"`
	Name        string          `json:"name"`
	Title       string          `json:"title,omitempty"`
	Description string          `json:"description,omitempty"`
	MIMEType    string          `json:"mimeType,omitempty"`
	Size        *int64          `json:"size,omitempty"`
}
type ResourceContents struct {
	Meta     json.RawMessage `json:"_meta,omitempty"`
	URI      string          `json:"uri"`
	MIMEType string          `json:"mimeType,omitempty"`
	Text     string          `json:"text,omitempty"`
	Blob     string          `json:"blob,omitempty"`
}
type Content struct {
	Type     string `json:"type"`
	Text     string `json:"text,omitempty"`
	Data     string `json:"data,omitempty"`
	MIMEType string `json:"mimeType,omitempty"`
}

func Decode[T any](data json.RawMessage) (T, error) {
	var value T
	if len(bytes.TrimSpace(data)) == 0 {
		data = []byte("{}")
	}
	err := json.Unmarshal(data, &value)
	return value, err
}
