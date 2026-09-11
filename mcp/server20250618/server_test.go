package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcptypes "github.com/therootcompany/golib/mcp/types20250618"
)

func TestServeHTTPRejectsBatch(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader("[]"))
	req.Header.Set("Accept", "application/json, text/event-stream")
	res := httptest.NewRecorder()

	(&MCPServer{}).ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusBadRequest)
	}
}

func TestServeHTTPRequiresAcceptTypes(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	res := httptest.NewRecorder()

	(&MCPServer{}).ServeHTTP(res, req)

	if res.Code != http.StatusNotAcceptable {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusNotAcceptable)
	}
}

func TestServeHTTPRejectsUntrustedOrigin(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Origin", "https://evil.example")
	res := httptest.NewRecorder()

	(&MCPServer{}).ServeHTTP(res, req)

	if res.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusForbidden)
	}
}

func TestServeHTTPRejectsUnsupportedProtocolVersion(t *testing.T) {
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("MCP-Protocol-Version", "2099-01-01")
	res := httptest.NewRecorder()

	(&MCPServer{}).ServeHTTP(res, req)

	if res.Code != http.StatusBadRequest {
		t.Fatalf("status = %d, want %d", res.Code, http.StatusBadRequest)
	}
}

func TestHandleRequestRejectsNullID(t *testing.T) {
	result := (&MCPServer{}).HandleRequest(nil, []byte(`{"jsonrpc":"2.0","id":null,"method":"tools/list"}`))

	errResponse, ok := result.(mcptypes.JSONRPCError)
	if !ok {
		t.Fatalf("result type = %T, want mcptypes.JSONRPCError", result)
	}
	if errResponse.Error.Code != mcptypes.ErrCodeInvalidRequest {
		t.Fatalf("error code = %d, want %d", errResponse.Error.Code, mcptypes.ErrCodeInvalidRequest)
	}
}

func TestHandleRequestAcceptsJSONRPCResponse(t *testing.T) {
	result := (&MCPServer{}).HandleRequest(nil, []byte(`{"jsonrpc":"2.0","id":1,"result":{}}`))
	if result != nil {
		t.Fatalf("result = %#v, want nil for accepted response", result)
	}
}

func TestToolsCallLeavesArgumentValidationToHandler(t *testing.T) {
	called := false
	srv := &MCPServer{}
	srv.HandleToolFunc("echo", mcptypes.Tool{
		InputSchema: mcptypes.ToolInputSchema{
			Type:     "object",
			Required: []string{"message"},
			Properties: map[string]mcptypes.Property{
				"message": {Type: "string"},
			},
		},
	}, func(context.Context, mcptypes.CallToolRequest) (*mcptypes.CallToolResult, error) {
		called = true
		return mcptypes.NewToolResultText("ok"), nil
	})

	result := srv.HandleRequest(nil, []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
	if _, ok := result.(mcptypes.JSONRPCResponse); !ok {
		t.Fatalf("result = %#v, want successful tool response", result)
	}
	if !called {
		t.Fatal("tool was not called; argument validation belongs to the handler")
	}
}

func TestResourceReadRejectsInvalidBlob(t *testing.T) {
	srv := &MCPServer{}
	srv.HandleResource("test://item", mcptypes.Resource{Name: "item"}, func(context.Context, mcptypes.ReadResourceRequest) ([]mcptypes.ResourceContents, error) {
		return []mcptypes.ResourceContents{{URI: "test://item", Blob: "not base64"}}, nil
	})
	result := srv.HandleRequest(nil, []byte(`{"jsonrpc":"2.0","id":1,"method":"resources/read","params":{"uri":"test://item"}}`))
	data, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(data), "invalid binary data") {
		t.Fatalf("result = %s, want invalid binary error", data)
	}
}

func TestInitializeNegotiatesCurrentVersion(t *testing.T) {
	srv := &MCPServer{Name: "test", Version: "1"}
	result := srv.HandleRequest(nil, []byte(`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"client","version":"1"}}}`))

	response, ok := result.(mcptypes.JSONRPCResponse)
	if !ok {
		t.Fatalf("result type = %T, want mcptypes.JSONRPCResponse", result)
	}
	initialize, ok := response.Result.(mcptypes.InitializeResult)
	if !ok {
		t.Fatalf("result payload type = %T, want mcptypes.InitializeResult", response.Result)
	}
	if initialize.ProtocolVersion != ProtocolVersion {
		t.Fatalf("protocol version = %q, want %q", initialize.ProtocolVersion, ProtocolVersion)
	}
}
