// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.
//
// SPDX-License-Identifier: MPL-2.0

// Example mcp-server-auth demonstrates how an MCP (Model Context Protocol)
// server verifies OAuth 2.1 access tokens from MCP clients.
//
// MCP uses OAuth 2.1 for authorization per the spec. This example shows:
//   - Bearer token extraction from Authorization headers
//   - JWT signature verification and claims validation
//   - Scope-based access control for MCP operations
//   - A JSON-RPC handler that lists tools or executes them based on granted scopes
//
// Run the server, then use the printed curl commands to test each scope level.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/therootcompany/golib/auth/jwt"
)

// MCP scope values for access control.
const (
	scopeRead  = "mcp:read"
	scopeWrite = "mcp:write"
	scopeAdmin = "mcp:admin"
)

// toolDef is the single source of truth for tool name, description, and
// required scope. Both tools/list and tools/call use this registry.
type toolDef struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Scope       string `json:"-"` // minimum scope required to see/call this tool
}

// toolRegistry is the canonical list of tools this server exposes.
var toolRegistry = []toolDef{
	{"search", "Search the knowledge base", scopeRead},
	{"summarize", "Summarize a document", scopeRead},
	{"create_document", "Create a new document", scopeWrite},
	{"manage_users", "Add or remove users from the workspace", scopeAdmin},
}

// --- Context accessors (two lines of code -- no library support required) ---

type contextKey string

const claimsKey contextKey = "claims"

// WithClaims returns a new context carrying the given token claims.
func WithClaims(ctx context.Context, c *jwt.TokenClaims) context.Context {
	return context.WithValue(ctx, claimsKey, c)
}

// ClaimsFromContext extracts claims stashed by the auth middleware.
func ClaimsFromContext(ctx context.Context) (*jwt.TokenClaims, bool) {
	c, ok := ctx.Value(claimsKey).(*jwt.TokenClaims)
	return c, ok
}

// --- JSON-RPC types (minimal subset of the MCP protocol) ---

// JSONRPCRequest is a minimal JSON-RPC 2.0 request envelope.
type JSONRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// JSONRPCResponse is a minimal JSON-RPC 2.0 response envelope.
type JSONRPCResponse struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id"`
	Result  any             `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Application-level JSON-RPC error codes (outside the -32768..-32000 reserved range).
const (
	errCodeForbidden = -31403 // insufficient scope
)

func main() {
	// --- Setup: self-signed key pair for demonstration ---
	pk, err := jwt.NewPrivateKey()
	if err != nil {
		log.Fatal(err)
	}
	signer, err := jwt.NewSigner([]*jwt.PrivateKey{pk})
	if err != nil {
		log.Fatal(err)
	}
	verifier := signer.Verifier()

	// The validator checks standard access token claims per RFC 9068.
	// In production, iss and aud would match your authorization server
	// and MCP server resource identifier.
	validator := jwt.NewAccessTokenValidator(
		[]string{"https://auth.example.com"},        // expected issuers
		[]string{"https://mcp.example.com/jsonrpc"}, // expected audiences
		0, // grace period (0 = default 2s)
	)

	// --- Auth middleware: verify signature + validate claims ---
	authMiddleware := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			auth := r.Header.Get("Authorization")
			if !strings.HasPrefix(auth, "Bearer ") {
				http.Error(w, "missing bearer token", http.StatusUnauthorized)
				return
			}
			tokenStr := strings.TrimPrefix(auth, "Bearer ")

			jws, err := jwt.Decode(tokenStr)
			if err != nil {
				http.Error(w, "bad token", http.StatusUnauthorized)
				return
			}
			if err := verifier.Verify(jws); err != nil {
				http.Error(w, "invalid signature", http.StatusUnauthorized)
				return
			}

			var claims jwt.TokenClaims
			if err := jws.UnmarshalClaims(&claims); err != nil {
				http.Error(w, "bad claims", http.StatusUnauthorized)
				return
			}
			if err := validator.Validate(nil, &claims, time.Now()); err != nil {
				http.Error(w, "invalid claims: "+err.Error(), http.StatusUnauthorized)
				return
			}

			next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), &claims)))
		})
	}

	// --- MCP JSON-RPC handler ---
	mcpHandler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		claims, ok := ClaimsFromContext(r.Context())
		if !ok {
			http.Error(w, "no claims in context", http.StatusInternalServerError)
			return
		}

		var req JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeRPCError(w, []byte("null"), -32700, "parse error")
			return
		}
		if req.JSONRPC != "2.0" {
			writeRPCError(w, req.ID, -32600, "invalid request: expected jsonrpc 2.0")
			return
		}

		switch req.Method {
		case "tools/list":
			handleToolsList(w, req, claims)
		case "tools/call":
			handleToolsCall(w, req, claims)
		default:
			writeRPCError(w, req.ID, -32601, fmt.Sprintf("method not found: %s", req.Method))
		}
	})

	mux := http.NewServeMux()
	mux.Handle("/mcp", authMiddleware(mcpHandler))

	// --- Mint demo tokens at each scope level ---
	now := time.Now()
	scopes := []struct {
		label string
		scope jwt.SpaceDelimited
	}{
		{"read-only", jwt.SpaceDelimited{scopeRead}},
		{"read-write", jwt.SpaceDelimited{scopeRead, scopeWrite}},
		{"admin", jwt.SpaceDelimited{scopeRead, scopeWrite, scopeAdmin}},
	}

	fmt.Println("MCP server listening on :8080")
	fmt.Println()
	for _, s := range scopes {
		token, err := signer.SignToString(&jwt.TokenClaims{
			Iss:      "https://auth.example.com",
			Sub:      "client-agent-1",
			Aud:      jwt.Listish{"https://mcp.example.com/jsonrpc"},
			Exp:      now.Add(time.Hour).Unix(),
			IAt:      now.Unix(),
			JTI:      fmt.Sprintf("tok-%s", s.label),
			ClientID: "mcp-client-demo",
			Scope:    s.scope,
		})
		if err != nil {
			log.Fatal(err)
		}
		fmt.Printf("--- %s token ---\n", s.label)
		fmt.Printf("curl -s -X POST http://localhost:8080/mcp \\\n")
		fmt.Printf("  -H 'Authorization: Bearer %s' \\\n", token)
		fmt.Printf("  -H 'Content-Type: application/json' \\\n")
		fmt.Printf("  -d '{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"tools/list\"}'\n\n")
	}

	log.Fatal(http.ListenAndServe(":8080", mux))
}

// handleToolsList returns the tools visible to the caller based on scopes.
func handleToolsList(w http.ResponseWriter, req JSONRPCRequest, claims *jwt.TokenClaims) {
	var visible []toolDef
	for _, td := range toolRegistry {
		if hasScope(claims, td.Scope) {
			visible = append(visible, td)
		}
	}

	writeRPCResult(w, req.ID, map[string]any{
		"tools": visible,
	})
}

// CallParams holds the parameters for a tools/call request.
type CallParams struct {
	Name string `json:"name"`
}

// handleToolsCall executes a tool if the caller has the required scope.
func handleToolsCall(w http.ResponseWriter, req JSONRPCRequest, claims *jwt.TokenClaims) {
	var params CallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		writeRPCError(w, req.ID, -32602, "invalid params")
		return
	}

	// Look up the tool in the single registry.
	var found *toolDef
	for i := range toolRegistry {
		if toolRegistry[i].Name == params.Name {
			found = &toolRegistry[i]
			break
		}
	}
	if found == nil {
		writeRPCError(w, req.ID, -32602, fmt.Sprintf("unknown tool: %s", params.Name))
		return
	}
	if !hasScope(claims, found.Scope) {
		writeRPCError(w, req.ID, errCodeForbidden, fmt.Sprintf("insufficient scope: %s required", found.Scope))
		return
	}

	writeRPCResult(w, req.ID, map[string]any{
		"content": []map[string]string{
			{"type": "text", "text": fmt.Sprintf("executed %s for %s", params.Name, claims.Sub)},
		},
	})
}

// hasScope checks whether the token's scope claim contains the given value.
func hasScope(claims *jwt.TokenClaims, scope string) bool {
	return slices.Contains(claims.Scope, scope)
}

func writeRPCResult(w http.ResponseWriter, id json.RawMessage, result any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Result:  result,
	})
}

func writeRPCError(w http.ResponseWriter, id json.RawMessage, code int, message string) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(JSONRPCResponse{
		JSONRPC: "2.0",
		ID:      id,
		Error:   &RPCError{Code: code, Message: message},
	})
}
