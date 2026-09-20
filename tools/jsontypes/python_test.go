package jsontypes

import (
	"strings"
	"testing"
)

func TestGeneratePythonFlat(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".age{int}",
		".active{bool}",
	}
	out := GeneratePython(paths)
	assertContainsAll(t, out,
		"from typing import TypedDict",
		"class Root(TypedDict):",
		"name: str",
		"age: int",
		"active: bool",
	)
}

func TestGeneratePythonOptional(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".bio{string?}",
	}
	out := GeneratePython(paths)
	assertContainsAll(t, out,
		"from typing import NotRequired, TypedDict",
		"name: str",
		"bio: NotRequired[str | None]",
	)
}

func TestGeneratePythonNested(t *testing.T) {
	paths := []string{
		"{Root}",
		".addr{Address}",
		".addr.city{string}",
	}
	out := GeneratePython(paths)
	assertContainsAll(t, out,
		"class Root(TypedDict):",
		"addr: Address",
		"class Address(TypedDict):",
		"city: str",
	)
	// Address should be defined before Root
	addrIdx := strings.Index(out, "class Address")
	rootIdx := strings.Index(out, "class Root")
	if addrIdx < 0 || rootIdx < 0 || addrIdx > rootIdx {
		t.Errorf("Address should be defined before Root\n%s", out)
	}
}

func TestGeneratePythonArray(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[].id{string}",
	}
	out := GeneratePython(paths)
	assertContainsAll(t, out,
		"items: list[Item]",
	)
}

func TestGeneratePythonMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".scores[string]{Score}",
		".scores[string].value{int}",
	}
	out := GeneratePython(paths)
	assertContainsAll(t, out,
		"scores: dict[str, Score]",
	)
}

func TestGeneratePythonEmpty(t *testing.T) {
	out := GeneratePython(nil)
	if out != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}

func TestGeneratePythonEndToEnd(t *testing.T) {
	jsonStr := `{"name":"Alice","age":30,"tags":["a"],"meta":{"key":"val"}}`
	paths := analyzeAndFormat(t, jsonStr)
	out := GeneratePython(paths)
	assertContainsAll(t, out,
		"class",
		"TypedDict",
		"name: str",
		"age: int",
	)
}
