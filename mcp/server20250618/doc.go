// Package mcpserver implements an MCP (Model Context Protocol) JSON-RPC server
// with a routing layer modeled after Go's HTTP middleware pattern.
//
// # Routing
//
// The routing table can live alongside the HTTP mux, so every tool, resource,
// and auth requirement is visible in one place:
//
//	srv := &mcpserver.MCPServer{Name: "example", Version: "1"}
//	mux := mcpserver.NewMux(srv, authMiddleware)
//	mux.Register("tools/example", mcpserver.ToolHandler{Tool: tool, Handle: handler})
//	mux.Method("tools/list", mux.ToolsIndex())
//	resources := mux.Resources()
//	resources.Expose("example://item", mcpserver.ResourceHandler{Resource: resource, Handle: read})
//	http.Handle("POST /mcp", srv)
//
// Three verbs for three concepts:
//   - [Mux.Register] — register tools on the server (tools/call dispatch)
//   - [Mux.Method] — override a JSON-RPC method handler (tools/list, resources/list)
//   - [ResourceMux.Expose] — expose resources for clients to read (resources/read dispatch)
//
// # Handler types
//
//   - [ToolHandler] — tool definition + handler func. Registered with a
//     "tools/" prefix that is stripped before reaching the wire.
//   - [ResourceHandler] — resource definition + handler func. Exposed
//     via [ResourceMux] keyed by URI.
//
// # Auth
//
// Authentication is enforced at the HTTP boundary, not inside the MCP server.
// The RequireBearer middleware (in the mcpserver package) verifies JWTs and
// returns 401 + WWW-Authenticate for OAuth discovery. This is visible in
// main.go's routing table alongside other HTTP middleware chains.
//
// # Wire format
//
// The "tools/" prefix is a routing table convention that makes registrations
// self-documenting. It is stripped before registration on [MCPServer] —
// tool names on the wire contain no prefix. Resource URIs are passed
// through as-is.
package mcpserver
