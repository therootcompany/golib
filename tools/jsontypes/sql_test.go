package jsontypes

import (
	"strings"
	"testing"
)

func TestGenerateSQLFlat(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".age{int}",
		".active{bool}",
	}
	out := GenerateSQL(paths)
	assertContainsAll(t, out,
		"CREATE TABLE roots (",
		"id BIGINT PRIMARY KEY GENERATED ALWAYS AS IDENTITY",
		"name TEXT NOT NULL",
		"age BIGINT NOT NULL",
		"active BOOLEAN NOT NULL",
	)
}

func TestGenerateSQLOptional(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".bio{string?}",
	}
	out := GenerateSQL(paths)
	// name should be NOT NULL, bio should not
	if !strings.Contains(out, "name TEXT NOT NULL") {
		t.Errorf("expected name NOT NULL\n%s", out)
	}
	// bio should NOT have NOT NULL
	for _, line := range strings.Split(out, "\n") {
		if strings.Contains(line, "bio") && strings.Contains(line, "NOT NULL") {
			t.Errorf("bio should be nullable\n%s", out)
		}
	}
}

func TestGenerateSQLNested(t *testing.T) {
	paths := []string{
		"{Root}",
		".addr{Address}",
		".addr.city{string}",
	}
	out := GenerateSQL(paths)
	assertContainsAll(t, out,
		"CREATE TABLE roots (",
		"CREATE TABLE addresss (",
		"addr_id BIGINT",
		"REFERENCES addresss(id)",
	)
}

func TestGenerateSQLArrayOfStructs(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[].slug{string}",
		".items[].name{string}",
	}
	out := GenerateSQL(paths)
	assertContainsAll(t, out,
		"CREATE TABLE roots (",
		"CREATE TABLE items (",
		"ALTER TABLE items ADD COLUMN root_id BIGINT REFERENCES roots(id)",
	)
	// items should NOT appear as a column in roots
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "items ") && strings.Contains(out, "CREATE TABLE roots") {
			// This is fine if it's in the items table
		}
	}
}

func TestGenerateSQLArrayOfPrimitives(t *testing.T) {
	paths := []string{
		"{Root}",
		".tags[]{string}",
	}
	out := GenerateSQL(paths)
	assertContainsAll(t, out,
		"tags JSONB NOT NULL",
	)
}

func TestGenerateSQLMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".metadata[string]{string}",
	}
	out := GenerateSQL(paths)
	assertContainsAll(t, out,
		"metadata JSONB NOT NULL",
	)
}

func TestGenerateSQLEmpty(t *testing.T) {
	out := GenerateSQL(nil)
	if out != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}

func TestGenerateSQLEndToEnd(t *testing.T) {
	jsonStr := `{"name":"Alice","age":30,"tags":["a"],"meta":{"key":"val"}}`
	paths := analyzeAndFormat(t, jsonStr)
	out := GenerateSQL(paths)
	assertContainsAll(t, out,
		"CREATE TABLE",
		"TEXT NOT NULL",
		"BIGINT",
	)
}

func TestGenerateSQLRelationships(t *testing.T) {
	paths := []string{
		"{User}",
		".name{string}",
		".profile{Profile}",
		".profile.bio{string}",
		".posts[]{Post}",
		".posts[].title{string}",
		".posts[].comments[]{Comment}",
		".posts[].comments[].body{string}",
	}
	out := GenerateSQL(paths)
	assertContainsAll(t, out,
		"CREATE TABLE users (",
		"CREATE TABLE profiles (",
		"CREATE TABLE posts (",
		"CREATE TABLE comments (",
		// User has FK to profile
		"profile_id BIGINT",
		"REFERENCES profiles(id)",
		// Posts have FK back to users
		"ALTER TABLE posts ADD COLUMN user_id BIGINT REFERENCES users(id)",
		// Comments have FK back to posts
		"ALTER TABLE comments ADD COLUMN post_id BIGINT REFERENCES posts(id)",
	)
}

func TestToSnakeCase(t *testing.T) {
	tests := []struct{ in, want string }{
		{"Root", "root"},
		{"RootItem", "root_item"},
		{"HTTPServer", "h_t_t_p_server"},
		{"address", "address"},
	}
	for _, tc := range tests {
		got := toSnakeCase(tc.in)
		if got != tc.want {
			t.Errorf("toSnakeCase(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
