package mcpserver

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"runtime/debug"
	"slices"
	"strings"
	"sync"
	"unicode"

	mcptypes "github.com/therootcompany/golib/mcp/types20250618"
)

const ProtocolVersion = "2025-06-18"

type ToolHandlerFunc func(ctx context.Context, request mcptypes.CallToolRequest) (*mcptypes.CallToolResult, error)
type ResourceHandlerFunc func(ctx context.Context, request mcptypes.ReadResourceRequest) ([]mcptypes.ResourceContents, error)

// MCPServer manages tool and resource registrations and dispatches JSON-RPC
// requests. It implements http.Handler.
type MCPServer struct {
	Name           string
	Title          string
	Version        string
	Instructions   string
	Capabilities   mcptypes.ServerCapabilities
	AllowedOrigins []string

	mu        sync.RWMutex
	tools     []registeredTool
	resources []registeredResource
	methods   map[string]MethodHandlerFunc // overrides for JSON-RPC methods
}

type registeredTool struct {
	tool    mcptypes.Tool
	handler ToolHandlerFunc
}

type registeredResource struct {
	resource mcptypes.Resource
	handler  ResourceHandlerFunc
}

type toolsListResult struct {
	Tools      []mcptypes.Tool `json:"tools"`
	NextCursor string          `json:"nextCursor,omitempty"`
}

type resourcesListResult struct {
	Resources  []mcptypes.Resource `json:"resources"`
	NextCursor string              `json:"nextCursor,omitempty"`
}

type resourcesReadResult struct {
	Contents []mcptypes.ResourceContents `json:"contents"`
}

// HandleToolFunc registers a tool and its handler. Panics on duplicate names.
func (s *MCPServer) HandleToolFunc(name string, tool mcptypes.Tool, handler ToolHandlerFunc) {
	tool.Name = name
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rt := range s.tools {
		if rt.tool.Name == name {
			panic(fmt.Sprintf("mcp: duplicate tool registration: %q", name))
		}
	}
	s.tools = append(s.tools, registeredTool{tool: tool, handler: handler})
}

func (s *MCPServer) HandleResource(uri string, resource mcptypes.Resource, handler ResourceHandlerFunc) {
	if err := validateResourceURI(uri); err != nil {
		panic(fmt.Sprintf("mcp: invalid resource URI %q: %v", uri, err))
	}
	resource.URI = uri
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, rr := range s.resources {
		if rr.resource.URI == uri {
			panic(fmt.Sprintf("mcp: duplicate resource registration: %q", uri))
		}
	}
	s.resources = append(s.resources, registeredResource{resource: resource, handler: handler})
}

// HandleMethod registers a method override (used by Mux for tools/list, etc.).
func (s *MCPServer) HandleMethod(method string, handler MethodHandlerFunc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.methods == nil {
		s.methods = make(map[string]MethodHandlerFunc)
	}
	if _, exists := s.methods[method]; exists {
		panic(fmt.Sprintf("mcp: duplicate method registration: %q", method))
	}
	s.methods[method] = handler
}

func (s *MCPServer) HandleRequest(ctx context.Context, raw json.RawMessage) any {
	var req mcptypes.JSONRPCRequest
	if err := json.Unmarshal(raw, &req); err != nil {
		return mcptypes.JSONRPCError{
			JSONRPC: mcptypes.JSONRPCVersion,
			ID:      nil,
			Error:   mcptypes.JSONRPCErrorDetails{Code: mcptypes.ErrCodeParse, Message: "Parse error"},
		}
	}

	var envelope map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return s.rpcError(nil, mcptypes.ErrCodeInvalidRequest, "Invalid JSON-RPC request")
	}
	if _, hasMethod := envelope["method"]; !hasMethod {
		_, hasResult := envelope["result"]
		_, hasError := envelope["error"]
		if (hasResult || hasError) && req.JSONRPC == mcptypes.JSONRPCVersion && req.IDPresent && req.ID != nil && !req.ID.IsNull() && hasResult != hasError {
			// HTTP transport accepts client responses but has no server-side request
			// correlation to perform here.
			return nil
		}
	}

	if req.JSONRPC != mcptypes.JSONRPCVersion || req.Method == "" || (req.IDPresent && (req.ID == nil || req.ID.IsNull())) {
		return s.rpcError(req.ID, mcptypes.ErrCodeInvalidRequest, "Invalid JSON-RPC request")
	}

	// Notifications (no id) are acknowledged without response.
	if req.IsNotification() {
		return nil
	}

	s.mu.RLock()
	mh := s.methods[req.Method]
	s.mu.RUnlock()
	if mh != nil {
		return mh(ctx, &req)
	}

	switch req.Method {
	case "initialize":
		return s.handleInitialize(ctx, &req)
	case "tools/list":
		return s.handleToolsList(ctx, &req)
	case "tools/call":
		return s.handleToolsCall(ctx, &req)
	case "resources/list":
		return s.handleResourcesList(ctx, &req)
	case "resources/read":
		return s.handleResourcesRead(ctx, &req)
	default:
		return s.rpcError(req.ID, mcptypes.ErrCodeMethodNotFound, fmt.Sprintf("Method not found: %s", req.Method))
	}
}

func (s *MCPServer) handleInitialize(_ context.Context, req *mcptypes.JSONRPCRequest) any {
	var params mcptypes.InitializeParams
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(req.Params, &params); err != nil || json.Unmarshal(req.Params, &fields) != nil || params.ProtocolVersion == "" || params.ClientInfo.Name == "" || params.ClientInfo.Version == "" {
		return s.rpcError(req.ID, mcptypes.ErrCodeInvalidParams, "Invalid params for initialize")
	}
	if _, ok := fields["capabilities"]; !ok {
		return s.rpcError(req.ID, mcptypes.ErrCodeInvalidParams, "Invalid params for initialize")
	}

	s.mu.RLock()
	capabilities := s.Capabilities
	if capabilities.Tools == nil && len(s.tools) > 0 {
		capabilities.Tools = &mcptypes.ToolsCapability{}
	}
	if capabilities.Resources == nil && len(s.resources) > 0 {
		capabilities.Resources = &mcptypes.ResourcesCapability{}
	}
	s.mu.RUnlock()

	result := mcptypes.InitializeResult{
		ProtocolVersion: ProtocolVersion,
		Capabilities:    capabilities,
		ServerInfo: mcptypes.ServerInfo{
			Name:    s.Name,
			Title:   s.Title,
			Version: s.Version,
		},
		Instructions: s.Instructions,
	}
	return s.rpcResult(req.ID, result)
}

func (s *MCPServer) handleToolsList(_ context.Context, req *mcptypes.JSONRPCRequest) any {
	s.mu.RLock()
	tools := make([]mcptypes.Tool, 0, len(s.tools))
	for _, rt := range s.tools {
		if isAppOnly(rt.tool) {
			continue
		}
		tools = append(tools, rt.tool)
	}
	s.mu.RUnlock()

	return s.rpcResult(req.ID, toolsListResult{Tools: tools})
}

// isAppOnly reports whether the tool's visibility is restricted to "app" only.
// Tools with visibility ["app"] are hidden from tools/list (they're only
// invoked by the embedded MCP App UI, not the LLM).
func isAppOnly(t mcptypes.Tool) bool {
	if t.Meta == nil || t.Meta.UI == nil || len(t.Meta.UI.Visibility) == 0 {
		return false
	}
	for _, v := range t.Meta.UI.Visibility {
		if v != "app" {
			return false
		}
	}
	return true
}

func (s *MCPServer) handleToolsCall(ctx context.Context, req *mcptypes.JSONRPCRequest) any {
	var params mcptypes.CallToolParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return s.rpcError(req.ID, mcptypes.ErrCodeInvalidParams, "Invalid params for tools/call")
	}

	if params.Arguments == nil {
		params.Arguments = make(map[string]any)
	}

	s.mu.RLock()
	var handler ToolHandlerFunc
	for _, rt := range s.tools {
		if rt.tool.Name == params.Name {
			handler = rt.handler
			break
		}
	}
	s.mu.RUnlock()

	if handler == nil {
		return s.rpcError(req.ID, mcptypes.ErrCodeInvalidParams, fmt.Sprintf("Unknown tool: %s", params.Name))
	}

	callReq := mcptypes.CallToolRequest{
		Params: params,
	}

	result, err := s.callToolWithRecovery(ctx, handler, callReq)

	if err != nil {
		log.Printf("[mcp] tool %q error: %v", params.Name, err)
		return s.rpcResult(req.ID, mcptypes.NewToolResultError("Tool execution failed"))
	}
	if result == nil {
		log.Printf("[mcp] tool %q returned a nil result", params.Name)
		return s.rpcResult(req.ID, mcptypes.NewToolResultError("Tool execution failed"))
	}
	return s.rpcResult(req.ID, result)
}

func (s *MCPServer) callToolWithRecovery(ctx context.Context, handler ToolHandlerFunc, req mcptypes.CallToolRequest) (result *mcptypes.CallToolResult, err error) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("[mcp] panic in tool %q: %v\n%s", req.Params.Name, r, debug.Stack())
			result = &mcptypes.CallToolResult{
				Content: []mcptypes.Content{mcptypes.TextContent{Type: "text", Text: fmt.Sprintf("Internal error: %v", r)}},
				IsError: true,
			}
			err = nil
		}
	}()
	return handler(ctx, req)
}

func (s *MCPServer) handleResourcesList(_ context.Context, req *mcptypes.JSONRPCRequest) any {
	s.mu.RLock()
	resources := make([]mcptypes.Resource, len(s.resources))
	for i, rr := range s.resources {
		resources[i] = rr.resource
	}
	s.mu.RUnlock()

	return s.rpcResult(req.ID, resourcesListResult{Resources: resources})
}

func (s *MCPServer) handleResourcesRead(ctx context.Context, req *mcptypes.JSONRPCRequest) any {
	var params mcptypes.ReadResourceParams
	if err := json.Unmarshal(req.Params, &params); err != nil || params.URI == "" {
		return s.rpcError(req.ID, mcptypes.ErrCodeInvalidParams, "Invalid params for resources/read")
	}
	if err := validateResourceURI(params.URI); err != nil {
		return s.rpcError(req.ID, mcptypes.ErrCodeInvalidParams, "Invalid resource URI")
	}

	s.mu.RLock()
	var handler ResourceHandlerFunc
	for _, rr := range s.resources {
		if rr.resource.URI == params.URI {
			handler = rr.handler
			break
		}
	}
	s.mu.RUnlock()

	if handler == nil {
		return s.rpcError(req.ID, mcptypes.ErrCodeResourceNotFound, fmt.Sprintf("Unknown resource: %s", params.URI))
	}

	readReq := mcptypes.ReadResourceRequest{
		Params: params,
	}

	contents, err := handler(ctx, readReq)
	if err != nil {
		log.Printf("[mcp] resource %q error: %v", params.URI, err)
		return s.rpcError(req.ID, mcptypes.ErrCodeInternal, "Resource read failed")
	}
	for _, content := range contents {
		if content.Blob != "" {
			if _, err := base64.StdEncoding.DecodeString(content.Blob); err != nil {
				return s.rpcError(req.ID, mcptypes.ErrCodeInternal, "Resource returned invalid binary data")
			}
		}
		if err := validateResourceURI(content.URI); err != nil {
			return s.rpcError(req.ID, mcptypes.ErrCodeInternal, "Resource returned invalid URI")
		}
	}

	return s.rpcResult(req.ID, resourcesReadResult{Contents: contents})
}

func (s *MCPServer) rpcResult(id *mcptypes.RequestID, result any) mcptypes.JSONRPCResponse {
	return mcptypes.JSONRPCResponse{
		JSONRPC: mcptypes.JSONRPCVersion,
		ID:      id,
		Result:  result,
	}
}

func (s *MCPServer) rpcError(id *mcptypes.RequestID, code int, message string) mcptypes.JSONRPCError {
	return mcptypes.JSONRPCError{
		JSONRPC: mcptypes.JSONRPCVersion,
		ID:      id,
		Error:   mcptypes.JSONRPCErrorDetails{Code: code, Message: message},
	}
}

func validateResourceURI(raw string) error {
	if raw == "" || strings.IndexFunc(raw, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) >= 0 {
		return fmt.Errorf("URI is empty or contains invalid characters")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Fragment != "" {
		return fmt.Errorf("URI must be absolute and must not contain a fragment")
	}
	return nil
}

const maxBodySize = 10 << 20 // 10 MB

func (s *MCPServer) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if origin := r.Header.Get("Origin"); origin != "" && !s.originAllowed(origin) {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if err := validateProtocolHeader(r); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !acceptsJSONOrSSE(r.Header.Get("Accept")) {
		http.Error(w, "Not Acceptable", http.StatusNotAcceptable)
		return
	}
	s.handlePost(w, r)
}

func (s *MCPServer) originAllowed(origin string) bool {
	return slices.Contains(s.AllowedOrigins, origin)
}

func validateProtocolHeader(r *http.Request) error {
	version := r.Header.Get("MCP-Protocol-Version")
	if version != "" && version != ProtocolVersion && version != "2025-03-26" {
		return fmt.Errorf("unsupported MCP protocol version: %s", version)
	}
	return nil
}

func acceptsJSONOrSSE(accept string) bool {
	if accept == "" {
		return false
	}
	var jsonOK, sseOK bool
	for value := range strings.SplitSeq(accept, ",") {
		mediaType := strings.TrimSpace(strings.SplitN(value, ";", 2)[0])
		switch mediaType {
		case "application/json":
			jsonOK = true
		case "text/event-stream":
			sseOK = true
		}
	}
	return jsonOK && sseOK
}

func (s *MCPServer) handlePost(w http.ResponseWriter, r *http.Request) {
	ctx := r.Context()

	body, err := io.ReadAll(io.LimitReader(r.Body, maxBodySize+1))
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	if len(body) > maxBodySize {
		w.WriteHeader(http.StatusRequestEntityTooLarge)
		return
	}

	body = trimSpace(body)
	if len(body) == 0 {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	if body[0] == '[' || !json.Valid(body) {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	result := s.HandleRequest(ctx, body)
	if result == nil {
		w.WriteHeader(http.StatusAccepted)
		return
	}

	writeJSON(w, http.StatusOK, result)
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		log.Printf("[mcp] failed to encode response: %v", err)
	}
}

func writeJSONError(w http.ResponseWriter, id *mcptypes.RequestID, code int, message string) {
	writeJSON(w, http.StatusOK, mcptypes.JSONRPCError{
		JSONRPC: mcptypes.JSONRPCVersion,
		ID:      id,
		Error:   mcptypes.JSONRPCErrorDetails{Code: code, Message: message},
	})
}

func trimSpace(b []byte) []byte {
	for len(b) > 0 && (b[0] == ' ' || b[0] == '\t' || b[0] == '\n' || b[0] == '\r') {
		b = b[1:]
	}
	return b
}
