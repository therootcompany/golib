// Package mcpserver implements the stateless MCP 2026-07-28 protocol.
//
// The HTTP transport checks Mcp-Method and Mcp-Name before decoding the JSON
// body. Registered handlers receive concrete Go parameter and result types;
// application code does not need a JSON Schema validator or map[string]any.
//
// A typical server registers typed tools and resources:
//
//	srv := &mcpserver.MCPServer{Name: "example", Version: "1"}
//	mcpserver.RegisterTypedTool(srv, mcptypes.Tool{Name: "echo"}, func(ctx context.Context, headers mcpserver.Headers, args EchoArgs) (mcptypes.CallToolResult, error) {
//		return TextResult(args.Message), nil
//	})
//
// Use the request headers for transport-level routing and custom tool headers;
// use typed request decoding for the JSON parameters.
package mcpserver
