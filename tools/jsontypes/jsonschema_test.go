package jsontypes

import (
	"encoding/json"
	"testing"
)

func TestGenerateJSONSchemaFlat(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".age{int}",
		".active{bool}",
	}
	out := GenerateJSONSchema(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc["$schema"] != "https://json-schema.org/draft/2020-12/schema" {
		t.Errorf("missing or wrong $schema")
	}
	if doc["type"] != "object" {
		t.Errorf("expected type=object, got %v", doc["type"])
	}
	props := doc["properties"].(map[string]any)
	assertJSType(t, props, "name", "string")
	assertJSType(t, props, "age", "integer")
	assertJSType(t, props, "active", "boolean")

	// Check required
	req := doc["required"].([]any)
	reqSet := make(map[string]bool)
	for _, r := range req {
		reqSet[r.(string)] = true
	}
	for _, f := range []string{"name", "age", "active"} {
		if !reqSet[f] {
			t.Errorf("expected %q in required", f)
		}
	}
}

func TestGenerateJSONSchemaNested(t *testing.T) {
	paths := []string{
		"{Root}",
		".addr{Address}",
		".addr.city{string}",
		".addr.zip{string}",
	}
	out := GenerateJSONSchema(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	props := doc["properties"].(map[string]any)
	addr := props["addr"].(map[string]any)
	if addr["$ref"] != "#/$defs/Address" {
		t.Errorf("expected $ref=#/$defs/Address, got %v", addr)
	}
	defs := doc["$defs"].(map[string]any)
	addrDef := defs["Address"].(map[string]any)
	addrProps := addrDef["properties"].(map[string]any)
	assertJSType(t, addrProps, "city", "string")
}

func TestGenerateJSONSchemaArray(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[].id{string}",
	}
	out := GenerateJSONSchema(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	props := doc["properties"].(map[string]any)
	items := props["items"].(map[string]any)
	if items["type"] != "array" {
		t.Errorf("expected type=array, got %v", items["type"])
	}
	itemsItems := items["items"].(map[string]any)
	if itemsItems["$ref"] != "#/$defs/Item" {
		t.Errorf("expected items.$ref=#/$defs/Item, got %v", itemsItems)
	}
}

func TestGenerateJSONSchemaOptional(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".bio{string?}",
	}
	out := GenerateJSONSchema(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	props := doc["properties"].(map[string]any)
	bio := props["bio"].(map[string]any)
	anyOf := bio["anyOf"].([]any)
	if len(anyOf) != 2 {
		t.Fatalf("expected 2 anyOf entries, got %d", len(anyOf))
	}
	// bio should not be in required
	req := doc["required"].([]any)
	for _, r := range req {
		if r.(string) == "bio" {
			t.Errorf("bio should not be in required")
		}
	}
}

func TestGenerateJSONSchemaMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".scores[string]{Score}",
		".scores[string].value{int}",
	}
	out := GenerateJSONSchema(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	props := doc["properties"].(map[string]any)
	scores := props["scores"].(map[string]any)
	if scores["type"] != "object" {
		t.Errorf("expected type=object for map, got %v", scores["type"])
	}
	addl := scores["additionalProperties"].(map[string]any)
	if addl["$ref"] != "#/$defs/Score" {
		t.Errorf("expected additionalProperties.$ref=#/$defs/Score, got %v", addl)
	}
}

func TestGenerateJSONSchemaEmpty(t *testing.T) {
	out := GenerateJSONSchema(nil)
	if out != "{}\n" {
		t.Errorf("expected empty schema, got %q", out)
	}
}

func TestGenerateJSONSchemaEndToEnd(t *testing.T) {
	jsonStr := `{"name":"Alice","age":30,"tags":["a","b"],"meta":{"key":"val"}}`
	paths := analyzeAndFormat(t, jsonStr)
	out := GenerateJSONSchema(paths)
	var doc map[string]any
	if err := json.Unmarshal([]byte(out), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, out)
	}
	if doc["type"] != "object" {
		t.Errorf("expected type=object at root: %s", out)
	}
}

func assertJSType(t *testing.T, props map[string]any, field, expected string) {
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
