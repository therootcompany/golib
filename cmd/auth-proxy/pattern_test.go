package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestMatchPattern(t *testing.T) {
	tests := []struct {
		grant  string
		method string
		host   string
		path   string
		want   bool
	}{
		// Basic path matching
		{"/", "GET", "example.com", "/", true},
		{"GET:/", "POST", "example.com", "/", false},
		{"/api/users", "GET", "api.example.com", "/api/users", true},
		{"/api/users", "GET", "api.example.com", "/api/users/", true},
		{"/api/users", "GET", "api.example.com", "/api/users", true},
		{"/api/users/", "GET", "", "/api/users", true},

		// Host matching
		{"example.com/", "GET", "example.com", "/", true},
		{"GET:example.com/", "GET", "example.com", "/", true},
		{"whatever.net/", "GET", "example.com", "/", false},
		{"example.comz/", "GET", "example.com", "/", false},
		{"example.com/", "GET", "example.comz", "/", false},
		{"aexample.com/", "GET", "example.com", "/", false},
		{"example.com/", "GET", "aexample.com", "/", false},
		{"example.com/", "GET", "api.example.com", "/", false},
		{"api.example.com/", "GET", "example.com", "/", false},
		{".example.com/", "GET", "api.example.com", "/", false},
		{"api.example.com/", "GET", "", "/", false},
		{"GET:api.example.com/", "GET", "example.com", "/", false},
		{"example.com/", "GET", "example.com:443", "/", true},
		{"GET:example.com/", "GET", "example.com:443", "/", true},

		// Method lists
		{"GET,POST,PUT:/api", "POST", "", "/api", true},
		{"GET,DELETE:/api", "POST", "", "/api", false},

		// Wildcard / placeholder segments
		// bad
		{"/users/{id}", "GET", "", "/user", false},
		// good
		{"/users/{id}", "GET", "", "/users", true},
		{"/users/{id}", "GET", "", "/users/", true},
		{"/users/{id}", "GET", "", "/users/123", true},
		{"/users/{id}", "GET", "", "/users/123/", true},
		{"/users/{id}", "GET", "", "/users/123/friends", true},
		// bad
		{"/users/{id}/", "GET", "", "/user", false},
		// good
		{"/users/{id}/", "GET", "", "/users", true},
		{"/users/{id}/", "GET", "", "/users/", true},
		{"/users/{id}/", "GET", "", "/users/123", true},
		{"/users/{id}/", "GET", "", "/users/123/", true},
		{"/users/{id}/", "GET", "", "/users/123/friends", true},
		// good (these are exactly the same as /path/{var} above, but added for completeness)
		{"/users/{id...}", "GET", "", "/users", true},
		{"/users/{id...}", "GET", "", "/users/", true},
		{"/users/{id...}", "GET", "", "/users/123", true},
		{"/users/{id...}", "GET", "", "/users/123/", true},
		{"/users/{id...}", "GET", "", "/users/123/friends", true},
		// good
		{"/users/{id}", "GET", "", "/users/123/bar", true},
		{"/users/{id}", "GET", "", "/users/123/bar/", true},
		{"/users/{id}", "GET", "", "/users/123/bar/456", true},
		{"/users/{id}", "GET", "", "/users/123/bar", true},
		{"/users/{id}", "GET", "", "/users/123/bar/", true},
		{"/users/{id}", "GET", "", "/users/123/bar/456", true},
		// good
		{"/users/{id}/{$}", "GET", "", "/users/123", true},
		{"/users/{id}/{$}", "GET", "", "/users/123/", true},
		// wrong
		{"/users/{id}/bar", "GET", "", "/users/123", false},
		{"/users/{id}/bar", "GET", "", "/users/123/", false},
		{"/users/{id}/bar", "GET", "", "/users/123/b", false},
		{"/users/{id}/bar", "GET", "", "/users/123/b/", false},
		{"/users/{id}/bar", "GET", "", "/users/123/b/456", false},
		{"/users/{id}/{$}", "GET", "", "/users/123/b", false},
		// {$}
		{"/api/{ver}/items/{$}", "GET", "", "/api/v1/items", true},
		{"/api/{ver}/items/{$}", "GET", "", "/api/v1/items/", true},
		{"/api/{ver}/items/{$}", "GET", "", "/api/v1/items/42", false},
		{"/foo/{$}/baz", "GET", "", "/foo/bar/baz", false},

		// Edge cases & invalid patterns
		{"", "GET", "example.com", "/", false},
		{"", "GET", "", "/", false},
		{"GET", "GET", "example.com", "/", false},
		{"GET:", "GET", "example.com", "/", false},
		{"example.com", "GET", "example.com", "/", false},
		{"GET:example.com", "GET", "example.com", "/", false},
		{"GET:/users ", "GET", "", "/users", true},
	}

	for _, tt := range tests {
		// name := "Pattern " + tt.grant + " vs URI " + strings.TrimSpace(fmt.Sprintf("%s %s%s", tt.method, tt.host, tt.path))
		name := tt.grant + " vs " + strings.TrimSpace(fmt.Sprintf("%s %s%s", tt.method, tt.host, tt.path))
		t.Run(name, func(t *testing.T) {
			got := matchPattern(tt.grant, tt.method, tt.host, tt.path)
			if got != tt.want {
				t.Errorf("matchPattern(%q, %q, %q, %q) = %v, want %v",
					tt.grant, tt.method, tt.host, tt.path, got, tt.want)
			}
		})
	}
}
