package jsontypes

import (
	"strings"
	"testing"
)

func TestGenerateJSDocFlat(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".age{int}",
		".active{bool}",
	}
	out := GenerateJSDoc(paths)
	assertContainsAll(t, out,
		"@typedef {Object} Root",
		"@property {string} name",
		"@property {number} age",
		"@property {boolean} active",
	)
}

func TestGenerateJSDocOptional(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".bio{string?}",
	}
	out := GenerateJSDoc(paths)
	assertContainsAll(t, out,
		"@property {string} name",
		"@property {string} [bio]",
	)
}

func TestGenerateJSDocNested(t *testing.T) {
	paths := []string{
		"{Root}",
		".addr{Address}",
		".addr.city{string}",
	}
	out := GenerateJSDoc(paths)
	assertContainsAll(t, out,
		"@typedef {Object} Root",
		"@property {Address} addr",
		"@typedef {Object} Address",
		"@property {string} city",
	)
}

func TestGenerateJSDocArray(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[].id{string}",
	}
	out := GenerateJSDoc(paths)
	assertContainsAll(t, out,
		"@property {Item[]} items",
	)
}

func TestGenerateJSDocMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".scores[string]{Score}",
		".scores[string].value{int}",
	}
	out := GenerateJSDoc(paths)
	assertContainsAll(t, out,
		"@property {Object<string, Score>} scores",
	)
}

func TestGenerateJSDocEmpty(t *testing.T) {
	out := GenerateJSDoc(nil)
	if out != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}

func TestGenerateJSDocEndToEnd(t *testing.T) {
	jsonStr := `{"name":"Alice","age":30,"tags":["a"],"meta":{"key":"val"}}`
	paths := analyzeAndFormat(t, jsonStr)
	out := GenerateJSDoc(paths)
	assertContainsAll(t, out,
		"@typedef {Object}",
		"@property {string} name",
		"@property {number} age",
	)
}

func assertContainsAll(t *testing.T, got string, wants ...string) {
	t.Helper()
	for _, want := range wants {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q\ngot:\n%s", want, got)
		}
	}
}
