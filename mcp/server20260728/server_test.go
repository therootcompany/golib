package mcpserver

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mcptypes "github.com/therootcompany/golib/mcp/types20260728"
)

type echoArgs struct {
	Message string `json:"message"`
}

func (a echoArgs) Validate() error {
	if a.Message == "" {
		return errors.New("message is required")
	}
	return nil
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

func TestTypedMiddlewareReceivesValidatedArguments(t *testing.T) {
	srv := &MCPServer{}
	called := false
	middleware := func(next TypedToolHandler[echoArgs]) TypedToolHandler[echoArgs] {
		return func(ctx context.Context, headers Headers, args echoArgs) (mcptypes.CallToolResult, error) {
			if args.Message != "hello" {
				t.Fatalf("middleware args = %#v", args)
			}
			called = true
			return next(ctx, headers, args)
		}
	}
	RegisterTypedToolWithMiddleware(srv, mcptypes.Tool{Name: "echo"}, func(context.Context, Headers, echoArgs) (mcptypes.CallToolResult, error) {
		return mcptypes.NewToolResultText("ok"), nil
	}, middleware)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{"message":"hello"}}}`))
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "echo")
	srv.ServeHTTP(httptest.NewRecorder(), req)
	if !called {
		t.Fatal("typed middleware was not called")
	}
}

func TestServeHTTPContainsToolPanic(t *testing.T) {
	srv := &MCPServer{}
	srv.RegisterTool(mcptypes.Tool{Name: "panic"}, func(context.Context, CallToolRequest) (mcptypes.CallToolResult, error) {
		panic("boom")
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"panic"}}`))
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "panic")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	var response struct {
		Result mcptypes.CallToolResult `json:"result"`
	}
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if !response.Result.IsError {
		t.Fatal("panic did not become an in-band tool error")
	}
}

func TestServeHTTPRejectsInvalidTypedArguments(t *testing.T) {
	srv := &MCPServer{}
	RegisterTypedTool(srv, mcptypes.Tool{Name: "echo"}, func(context.Context, Headers, echoArgs) (mcptypes.CallToolResult, error) {
		return mcptypes.NewToolResultText("ok"), nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"echo","arguments":{}}}`))
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "echo")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	var response mcptypes.ErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != mcptypes.ErrInvalidParams {
		t.Fatalf("code = %d, want %d", response.Error.Code, mcptypes.ErrInvalidParams)
	}
}

func TestRegisterResourceRejectsInvalidURI(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("invalid resource URI did not panic")
		}
	}()
	(&MCPServer{}).RegisterResource(mcptypes.Resource{URI: "not absolute"}, nil)
}

func TestServeHTTPRejectsAppOnlyToolsFromList(t *testing.T) {
	srv := &MCPServer{}
	srv.RegisterTool(mcptypes.Tool{Name: "hidden", Meta: &mcptypes.Meta{UI: &mcptypes.AppUI{Visibility: []mcptypes.Visibility{mcptypes.VisibilityApp}}}}, nil)
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/list"}`))
	req.Header.Set("Mcp-Method", "tools/list")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	if strings.Contains(res.Body.String(), "hidden") {
		t.Fatalf("app-only tool leaked into list: %s", res.Body)
	}
}

func TestServeHTTPRejectsHeaderNameMismatch(t *testing.T) {
	srv := &MCPServer{}
	srv.RegisterTool(mcptypes.Tool{Name: "echo"}, func(context.Context, CallToolRequest) (mcptypes.CallToolResult, error) {
		return mcptypes.NewToolResultText("ok"), nil
	})
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(`{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"other"}}`))
	req.Header.Set("Mcp-Method", "tools/call")
	req.Header.Set("Mcp-Name", "echo")
	res := httptest.NewRecorder()
	srv.ServeHTTP(res, req)
	var response mcptypes.ErrorResponse
	if err := json.NewDecoder(res.Body).Decode(&response); err != nil {
		t.Fatal(err)
	}
	if response.Error.Code != mcptypes.ErrHeaderMismatch {
		t.Fatalf("code = %d, want %d", response.Error.Code, mcptypes.ErrHeaderMismatch)
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
