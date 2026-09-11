package mcpserver

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcptypes "github.com/therootcompany/golib/mcp/types20260728"
)

type echoArgs struct {
	Message string `json:"message"`
}

func TestServeHTTPUsesHeadersBeforeTypedDecode(t *testing.T) {
	var got Headers
	var gotArgs echoArgs
	srv := &MCPServer{Name: "test", Version: "1"}
	RegisterTypedTool(srv, mcptypes.Tool{Name: "echo", InputSchema: json.RawMessage(`{"type":"object"}`)}, func(_ context.Context, headers Headers, args echoArgs) (mcptypes.CallToolResult, error) {
		got = headers
		gotArgs = args
		return mcptypes.CallToolResult{ResultType: "complete", Content: []mcptypes.Content{{Type: "text", Text: args.Message}}}, nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`))
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "echo")
	req.Header.Add("x-mcp-header", "trace-id")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", res.Code, res.Body)
	}
	if got.Method != "tools/call" || got.Name != "echo" || len(got.Custom["x-mcp-header"]) != 1 {
		t.Fatalf("headers = %#v", got)
	}
	if gotArgs.Message != "hello" {
		t.Fatalf("args = %#v", gotArgs)
	}
}

func TestServeHTTPRejectsHeaderMethodMismatch(t *testing.T) {
	srv := &MCPServer{}
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Mcp-Method", "tools/call")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if res.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200 JSON-RPC error", res.Code)
	}
	var response mcptypes.ErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != mcptypes.ErrHeaderMismatch {
		t.Fatalf("code = %d, want %d", response.Error.Code, mcptypes.ErrHeaderMismatch)
	}
}
