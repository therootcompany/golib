// Package mcpserver implements the stateless MCP 2026-07-28 server.
//
// HTTP headers are inspected before the JSON body is decoded. Mcp-Method and
// Mcp-Name select the protocol route; x-mcp-header values are made available
// to the selected handler.
package mcpserver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"slices"
	"strings"
	"sync"

	mcptypes "github.com/therootcompany/golib/mcp/types20260728"
)

const ProtocolVersion = mcptypes.ProtocolVersion

type Headers struct {
	Method string
	Name   string
	Custom map[string][]string
}

func headersFromHTTP(h http.Header) Headers {
	custom := make(map[string][]string)
	for key, values := range h {
		if strings.EqualFold(key, "x-mcp-header") {
			custom["x-mcp-header"] = append([]string(nil), values...)
		}
	}
	return Headers{Method: h.Get("Mcp-Method"), Name: h.Get("Mcp-Name"), Custom: custom}
}

type CallToolRequest struct {
	Headers Headers
	Params  mcptypes.CallToolParams
}
type ReadResourceRequest struct {
	Headers Headers
	Params  mcptypes.ReadResourceParams
}
type ToolHandlerFunc func(context.Context, CallToolRequest) (mcptypes.CallToolResult, error)
type ResourceHandlerFunc func(context.Context, ReadResourceRequest) (mcptypes.ReadResourceResult, error)

// RegisterTypedTool decodes a tool's arguments into T before calling handler.
// T is the application Go type for the tool input; no JSON Schema validator is
// involved.
func RegisterTypedTool[T any](s *MCPServer, definition mcptypes.Tool, handler func(context.Context, Headers, T) (mcptypes.CallToolResult, error)) {
	s.RegisterTool(definition, func(ctx context.Context, request CallToolRequest) (mcptypes.CallToolResult, error) {
		args, err := mcptypes.Decode[T](request.Params.Arguments)
		if err != nil {
			return mcptypes.CallToolResult{}, fmt.Errorf("decode %s arguments: %w", definition.Name, err)
		}
		return handler(ctx, request.Headers, args)
	})
}

type MCPServer struct {
	Name           string
	Title          string
	Version        string
	Instructions   string
	Capabilities   mcptypes.ServerCapabilities
	AllowedOrigins []string
	mu             sync.RWMutex
	tools          []registeredTool
	resources      []registeredResource
}
type registeredTool struct {
	definition mcptypes.Tool
	handler    ToolHandlerFunc
}
type registeredResource struct {
	definition mcptypes.Resource
	handler    ResourceHandlerFunc
}

func (s *MCPServer) RegisterTool(definition mcptypes.Tool, handler ToolHandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, tool := range s.tools {
		if tool.definition.Name == definition.Name {
			panic("mcp: duplicate tool: " + definition.Name)
		}
	}
	s.tools = append(s.tools, registeredTool{definition, handler})
}
func (s *MCPServer) RegisterResource(definition mcptypes.Resource, handler ResourceHandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, resource := range s.resources {
		if resource.definition.URI == definition.URI {
			panic("mcp: duplicate resource: " + definition.URI)
		}
	}
	s.resources = append(s.resources, registeredResource{definition, handler})
}

func (s *MCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.Header.Get("Mcp-Method") == "" {
		s.writeError(w, nil, mcptypes.ErrHeaderMismatch, "missing Mcp-Method header")
		return
	}
	if origin := r.Header.Get("Origin"); origin != "" && !contains(s.AllowedOrigins, origin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20+1))
	if err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if len(body) > 10<<20 {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	result := s.handle(r.Context(), headersFromHTTP(r.Header), body)
	if result == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(result)
}

func (s *MCPServer) handle(ctx context.Context, headers Headers, body []byte) any {
	var envelope struct {
		JSONRPC string              `json:"jsonrpc"`
		ID      *mcptypes.RequestID `json:"id"`
		Method  string              `json:"method"`
		Params  json.RawMessage     `json:"params"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		return s.error(nil, mcptypes.ErrParse, "Parse error")
	}
	if headers.Method != envelope.Method {
		return s.error(envelope.ID, mcptypes.ErrHeaderMismatch, "Mcp-Method does not match request method")
	}
	var request mcptypes.Request
	if err := json.Unmarshal(body, &request); err != nil || request.JSONRPC != mcptypes.JSONRPCVersion || request.Method == "" || (request.IDPresent && (request.ID == nil || request.ID.IsNull())) {
		return s.error(envelope.ID, mcptypes.ErrInvalidRequest, "Invalid JSON-RPC request")
	}
	if request.IsNotification() {
		return nil
	}
	switch request.Method {
	case "server/discover":
		return s.discover(envelope.ID)
	case "tools/list":
		return s.toolsList(envelope.ID)
	case "tools/call":
		return s.toolsCall(ctx, headers, envelope.ID, envelope.Params)
	case "resources/list":
		return s.resourcesList(envelope.ID)
	case "resources/read":
		return s.resourceRead(ctx, headers, envelope.ID, envelope.Params)
	default:
		return s.error(envelope.ID, mcptypes.ErrMethodNotFound, fmt.Sprintf("Method not found: %s", request.Method))
	}
}

func (s *MCPServer) discover(id *mcptypes.RequestID) any {
	value := mcptypes.DiscoverResult{ResultType: "complete", ProtocolVersions: []string{ProtocolVersion}, Capabilities: s.capabilities(), ServerInfo: mcptypes.ServerInfo{Name: s.Name, Title: s.Title, Version: s.Version}, Instructions: s.Instructions}
	raw, err := json.Marshal(value)
	if err != nil {
		return s.error(id, mcptypes.ErrInternal, "Failed to encode result")
	}
	return s.result(id, raw)
}
func (s *MCPServer) capabilities() mcptypes.ServerCapabilities {
	s.mu.RLock()
	defer s.mu.RUnlock()
	value := s.Capabilities
	if value.Tools == nil && len(s.tools) != 0 {
		value.Tools = &mcptypes.ToolsCapability{}
	}
	if value.Resources == nil && len(s.resources) != 0 {
		value.Resources = &mcptypes.ResourcesCapability{}
	}
	return value
}
func (s *MCPServer) toolsList(id *mcptypes.RequestID) any {
	s.mu.RLock()
	tools := make([]mcptypes.Tool, len(s.tools))
	for i := range s.tools {
		tools[i] = s.tools[i].definition
	}
	s.mu.RUnlock()
	raw, err := json.Marshal(mcptypes.ToolsListResult{ResultType: "complete", Tools: tools, CacheScope: mcptypes.CachePrivate})
	if err != nil {
		return s.error(id, mcptypes.ErrInternal, "Failed to encode result")
	}
	return s.result(id, raw)
}
func (s *MCPServer) toolsCall(ctx context.Context, headers Headers, id *mcptypes.RequestID, raw json.RawMessage) any {
	params, err := mcptypes.Decode[mcptypes.CallToolParams](raw)
	if err != nil || params.Name == "" {
		return s.error(id, mcptypes.ErrInvalidParams, "Invalid params for tools/call")
	}
	s.mu.RLock()
	var handler ToolHandlerFunc
	for _, tool := range s.tools {
		if tool.definition.Name == params.Name {
			handler = tool.handler
			break
		}
	}
	s.mu.RUnlock()
	if handler == nil {
		return s.error(id, mcptypes.ErrInvalidParams, "Unknown tool")
	}
	value, err := handler(ctx, CallToolRequest{headers, params})
	if err != nil {
		return s.error(id, mcptypes.ErrInternal, "Tool execution failed")
	}
	encoded, encodeErr := json.Marshal(value)
	if encodeErr != nil {
		return s.error(id, mcptypes.ErrInternal, "Failed to encode result")
	}
	return s.result(id, encoded)
}
func (s *MCPServer) resourcesList(id *mcptypes.RequestID) any {
	s.mu.RLock()
	resources := make([]mcptypes.Resource, len(s.resources))
	for i := range s.resources {
		resources[i] = s.resources[i].definition
	}
	s.mu.RUnlock()
	raw, err := json.Marshal(mcptypes.ResourcesListResult{ResultType: "complete", Resources: resources, CacheScope: mcptypes.CachePrivate})
	if err != nil {
		return s.error(id, mcptypes.ErrInternal, "Failed to encode result")
	}
	return s.result(id, raw)
}
func (s *MCPServer) resourceRead(ctx context.Context, headers Headers, id *mcptypes.RequestID, raw json.RawMessage) any {
	params, err := mcptypes.Decode[mcptypes.ReadResourceParams](raw)
	if err != nil || params.URI == "" {
		return s.error(id, mcptypes.ErrInvalidParams, "Invalid params for resources/read")
	}
	s.mu.RLock()
	var handler ResourceHandlerFunc
	for _, resource := range s.resources {
		if resource.definition.URI == params.URI {
			handler = resource.handler
			break
		}
	}
	s.mu.RUnlock()
	if handler == nil {
		return s.error(id, mcptypes.ErrInvalidParams, "Unknown resource")
	}
	value, err := handler(ctx, ReadResourceRequest{headers, params})
	if err != nil {
		return s.error(id, mcptypes.ErrInternal, "Resource read failed")
	}
	encoded, encodeErr := json.Marshal(value)
	if encodeErr != nil {
		return s.error(id, mcptypes.ErrInternal, "Failed to encode result")
	}
	return s.result(id, encoded)
}

func (s *MCPServer) result(id *mcptypes.RequestID, value json.RawMessage) mcptypes.Response {
	return mcptypes.Response{JSONRPC: mcptypes.JSONRPCVersion, ID: id, Result: value}
}
func (s *MCPServer) error(id *mcptypes.RequestID, code int, message string) mcptypes.ErrorResponse {
	return mcptypes.ErrorResponse{JSONRPC: mcptypes.JSONRPCVersion, ID: id, Error: mcptypes.ErrorObject{Code: code, Message: message}}
}
func (s *MCPServer) writeError(w http.ResponseWriter, id *mcptypes.RequestID, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(s.error(id, code, message))
}
func contains(values []string, target string) bool {
	return slices.Contains(values, target)
}
