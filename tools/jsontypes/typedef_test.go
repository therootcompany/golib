package jsontypes

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestGenerateTypedefFlat(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".age{int}",
		".active{bool}",
	}
	out := GenerateTypedef(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	props, ok := doc["properties"].(map[string]any)
	if !ok {
		t.Fatalf("expected properties, got %v", doc)
	}
	assertJTDType(t, props, "name", "string")
	assertJTDType(t, props, "age", "int32")
	assertJTDType(t, props, "active", "boolean")
}

func TestGenerateTypedefNested(t *testing.T) {
	paths := []string{
		"{Root}",
		".addr{Address}",
		".addr.city{string}",
		".addr.zip{string}",
	}
	out := GenerateTypedef(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	// addr should be a ref
	props := doc["properties"].(map[string]any)
	addr := props["addr"].(map[string]any)
	if addr["ref"] != "Address" {
		t.Errorf("expected ref=Address, got %v", addr)
	}
	// definitions should have Address
	defs := doc["definitions"].(map[string]any)
	addrDef := defs["Address"].(map[string]any)
	addrProps := addrDef["properties"].(map[string]any)
	assertJTDType(t, addrProps, "city", "string")
	assertJTDType(t, addrProps, "zip", "string")
}

func TestGenerateTypedefArray(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[].id{string}",
	}
	out := GenerateTypedef(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	props := doc["properties"].(map[string]any)
	items := props["items"].(map[string]any)
	elem := items["elements"].(map[string]any)
	if elem["ref"] != "Item" {
		t.Errorf("expected elements ref=Item, got %v", elem)
	}
}

func TestGenerateTypedefOptional(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".bio{string?}",
	}
	out := GenerateTypedef(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	optProps := doc["optionalProperties"].(map[string]any)
	bio := optProps["bio"].(map[string]any)
	if bio["nullable"] != true {
		t.Errorf("expected nullable=true for bio, got %v", bio)
	}
	if bio["type"] != "string" {
		t.Errorf("expected type=string for bio, got %v", bio["type"])
	}
}

func TestGenerateTypedefMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".scores[string]{Score}",
		".scores[string].value{int}",
	}
	out := GenerateTypedef(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	props := doc["properties"].(map[string]any)
	scores := props["scores"].(map[string]any)
	vals := scores["values"].(map[string]any)
	if vals["ref"] != "Score" {
		t.Errorf("expected values ref=Score, got %v", vals)
	}
}

func TestGenerateTypedefEmpty(t *testing.T) {
	out := GenerateTypedef(nil)
	if out != "{}\n" {
		t.Errorf("expected empty schema, got %q", out)
	}
}

func TestGenerateTypedefEndToEnd(t *testing.T) {
	jsonStr := `{"name":"Alice","age":30,"tags":["a","b"],"meta":{"key":"val"}}`
	paths := analyzeAndFormat(t, jsonStr)
	out := GenerateTypedef(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if _, ok := doc["properties"]; !ok {
		t.Errorf("expected properties in output: %s", out)
	}
}

func analyzeAndFormat(t *testing.T, jsonStr string) []string {
	t.Helper()
	var data any
	dec := json.NewDecoder(strings.NewReader(jsonStr))
	dec.UseNumber()
	if err := dec.Decode(&data); err != nil {
		t.Fatalf("invalid test JSON: %v", err)
	}
	a, err := NewAnalyzer(false, true, false)
	if err != nil {
		t.Fatalf("NewAnalyzer: %v", err)
	}
	defer a.Close()
	rawPaths := a.Analyze(".", data)
	return FormatPaths(rawPaths)
}

func assertJTDType(t *testing.T, props map[string]any, field, expected string) {
	t.Helper()
	f, ok := props[field].(map[string]any)
	if !ok {
		t.Errorf("field %q not found in properties", field)
		return
	}
	if f["type"] != expected {
		t.Errorf("field %q: expected type=%q, got %v", field, expected, f["type"])
	}
}
