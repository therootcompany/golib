package jsontypes

import (
	"strings"
	"testing"
)

func TestGenerateTypeScriptFlat(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".age{int}",
		".active{bool}",
	}
	out := GenerateTypeScript(paths)
	assertContains(t, out, "export interface Root {")
	assertContains(t, out, "name: string;")
	assertContains(t, out, "age: number;")
	assertContains(t, out, "active: boolean;")
}

func TestGenerateTypeScriptOptional(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".bio{string?}",
	}
	out := GenerateTypeScript(paths)
	assertContains(t, out, "name: string;")
	assertContains(t, out, "bio?: string | null;")
}

func TestGenerateTypeScriptNested(t *testing.T) {
	paths := []string{
		"{Root}",
		".addr{Address}",
		".addr.city{string}",
	}
	out := GenerateTypeScript(paths)
	assertContains(t, out, "addr: Address;")
	assertContains(t, out, "export interface Address {")
	assertContains(t, out, "city: string;")
}

func TestGenerateTypeScriptArray(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[].id{string}",
	}
	out := GenerateTypeScript(paths)
	assertContains(t, out, "items: Item[];")
}

func TestGenerateTypeScriptMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".scores[string]{Score}",
		".scores[string].value{int}",
	}
	out := GenerateTypeScript(paths)
	assertContains(t, out, "scores: Record<string, Score>;")
}

func TestGenerateTypeScriptEmpty(t *testing.T) {
	out := GenerateTypeScript(nil)
	if out != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}

func TestGenerateTypeScriptEndToEnd(t *testing.T) {
	jsonStr := `{"name":"Alice","age":30,"tags":["a"],"meta":{"key":"val"}}`
	paths := analyzeAndFormat(t, jsonStr)
	out := GenerateTypeScript(paths)
	assertContains(t, out, "export interface")
	assertContains(t, out, "name: string;")
	assertContains(t, out, "age: number;")
	assertContains(t, out, "tags: string[];")
}

func assertContains(t *testing.T, got, want string) {
	t.Helper()
	if !strings.Contains(got, want) {
		t.Errorf("output missing %q\ngot:\n%s", want, got)
	}
}
