package mcpserver

import (
	"context"
	"fmt"
	"strings"

	mcptypes "github.com/therootcompany/golib/mcp/types20260728"
)

// ToolExecution is a decoded tool invocation. Middleware may inspect the
// request headers and context, then call next to run the typed handler.
type ToolExecution func(context.Context, Headers) (mcptypes.CallToolResult, error)

// ToolMiddleware wraps decoded tool execution. It is suitable for middleware
// such as authentication that does not need the tool's argument type.
type ToolMiddleware func(ToolExecution) ToolExecution

// Registration is implemented by package-provided registration values such as
// ToolHandler[T]. Its method is intentionally private to keep registration
// behavior under package control.
type Registration interface {
	register(*MCPServer, []ToolMiddleware)
}

// ToolHandler pairs a tool definition with a validated Go argument type and
// typed handler. Use ToolHandler[T].With for middleware that needs T.
type ToolHandler[T mcptypes.Validatable] struct {
	Tool       mcptypes.Tool
	Handle     TypedToolHandler[T]
	Middleware []TypedToolMiddleware[T]
}

// With returns a copy with typed middleware appended.
func (h ToolHandler[T]) With(middleware ...TypedToolMiddleware[T]) ToolHandler[T] {
	h.Middleware = append(append([]TypedToolMiddleware[T](nil), h.Middleware...), middleware...)
	return h
}

func (h ToolHandler[T]) toolName() string { return h.Tool.Name }

func (h ToolHandler[T]) register(server *MCPServer, global []ToolMiddleware) {
	typed := h.Handle
	for i := len(h.Middleware) - 1; i >= 0; i-- {
		typed = h.Middleware[i](typed)
	}
	server.RegisterTool(h.Tool, func(ctx context.Context, request CallToolRequest) (mcptypes.CallToolResult, error) {
		args, err := mcptypes.DecodeValidated[T](request.Params.Arguments)
		if err != nil {
			return mcptypes.CallToolResult{}, fmt.Errorf("decode %s arguments: %w", h.Tool.Name, err)
		}
		execution := ToolExecution(func(ctx context.Context, headers Headers) (mcptypes.CallToolResult, error) {
			return typed(ctx, headers, args)
		})
		for i := len(global) - 1; i >= 0; i-- {
			execution = global[i](execution)
		}
		return execution(ctx, request.Headers)
	})
}

// Mux groups registrations on an MCPServer and creates middleware scopes.
type Mux struct {
	server     *MCPServer
	middleware []ToolMiddleware
}

func NewMux(server *MCPServer) *Mux { return &Mux{server: server} }

// With returns a new mux with additional middleware appended.
func (m *Mux) With(middleware ...ToolMiddleware) *Mux {
	combined := make([]ToolMiddleware, 0, len(m.middleware)+len(middleware))
	combined = append(combined, m.middleware...)
	combined = append(combined, middleware...)
	return &Mux{server: m.server, middleware: combined}
}

// Register registers a complete typed tool handler. The method string is a
// wiring label and must be tools/<tool name>, matching the name on the wire.
func (m *Mux) Register(method string, handler Registration) {
	if !strings.HasPrefix(method, "tools/") {
		panic("mcp: tool registered without tools/ prefix: " + method)
	}
	name := strings.TrimPrefix(method, "tools/")
	if tool, ok := handler.(interface{ toolName() string }); ok && tool.toolName() != name {
		panic(fmt.Sprintf("mcp: tool name mismatch: Register(%q) but Tool.Name is %q", method, tool.toolName()))
	}
	handler.register(m.server, m.middleware)
}

// RegisterTool registers a raw handler for protocol-level use. Typed tools
// should use Register with ToolHandler[T].
func (m *Mux) RegisterTool(definition mcptypes.Tool, handler ToolHandlerFunc) {
	m.server.RegisterTool(definition, handler)
}

// RegisterResource registers a resource read handler.
func (m *Mux) RegisterResource(definition mcptypes.Resource, handler ResourceHandlerFunc) {
	m.server.RegisterResource(definition, handler)
}
