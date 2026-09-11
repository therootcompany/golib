package mcpserver

import (
	"context"
	"fmt"
	"strings"

	mcptypes "github.com/therootcompany/golib/mcp/types20250618"
)

// ToolMiddleware wraps a tool handler, analogous to func(http.Handler) http.Handler.
type ToolMiddleware func(ToolHandlerFunc) ToolHandlerFunc

// ToolHandler pairs a tool definition with its handler function.
type ToolHandler struct {
	Tool   mcptypes.Tool
	Handle ToolHandlerFunc
}

// ResourceHandler pairs a resource definition with its read handler.
type ResourceHandler struct {
	Resource mcptypes.Resource
	Handle   ResourceHandlerFunc
}

// MethodHandlerFunc handles a raw JSON-RPC request for a specific method.
type MethodHandlerFunc func(ctx context.Context, req *mcptypes.JSONRPCRequest) any

// Mux composes middleware chains and registers tools on an MCPServer.
// Mirrors golib/http/middleware.MiddlewareMux: NewMux → .With() → .Register().
type Mux struct {
	server      *MCPServer
	middlewares []ToolMiddleware
}

func NewMux(srv *MCPServer, middlewares ...ToolMiddleware) *Mux {
	return &Mux{
		server:      srv,
		middlewares: middlewares,
	}
}

// With returns a new Mux with additional middlewares appended.
func (m *Mux) With(middlewares ...ToolMiddleware) *Mux {
	combined := make([]ToolMiddleware, 0, len(m.middlewares)+len(middlewares))
	combined = append(combined, m.middlewares...)
	combined = append(combined, middlewares...)
	return &Mux{
		server:      m.server,
		middlewares: combined,
	}
}

// Register registers a tool. The method must start with "tools/" — the prefix
// is stripped to produce the wire-format tool name. Panics on wiring errors.
func (m *Mux) Register(method string, th ToolHandler) {
	if !strings.HasPrefix(method, "tools/") {
		panic("mcp: tool registered without tools/ prefix: " + method)
	}
	name := strings.TrimPrefix(method, "tools/")
	if th.Tool.Name != "" && th.Tool.Name != name {
		panic(fmt.Sprintf("mcp: tool name mismatch: Register(%q) but Tool.Name is %q", method, th.Tool.Name))
	}

	handler := th.Handle
	for i := len(m.middlewares) - 1; i >= 0; i-- {
		handler = m.middlewares[i](handler)
	}
	m.server.HandleToolFunc(name, th.Tool, handler)
}

// Method overrides a built-in JSON-RPC method (e.g. "tools/list").
func (m *Mux) Method(method string, handler MethodHandlerFunc) {
	m.server.HandleMethod(method, handler)
}

// Resources returns a ResourceMux for resources/read.
func (m *Mux) Resources() *ResourceMux {
	return &ResourceMux{server: m.server}
}

// ToolsIndex returns a handler for tools/list.
func (m *Mux) ToolsIndex() MethodHandlerFunc {
	return m.server.handleToolsList
}

// ResourcesIndex returns a handler for resources/list.
func (m *Mux) ResourcesIndex() MethodHandlerFunc {
	return m.server.handleResourcesList
}

// ResourceMux registers resources on the server. Created via [Mux.Resources].
type ResourceMux struct {
	server *MCPServer
}

// Expose registers a resource by URI. Panics if the handler's URI doesn't match.
func (rm *ResourceMux) Expose(uri string, rh ResourceHandler) {
	if rh.Resource.URI != "" && rh.Resource.URI != uri {
		panic(fmt.Sprintf("mcp: resource URI mismatch: Expose(%q) but Resource.URI is %q", uri, rh.Resource.URI))
	}
	rm.server.HandleResource(uri, rh.Resource, rh.Handle)
}
