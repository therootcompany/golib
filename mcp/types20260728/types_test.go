package mcptypes

import (
	"encoding/json"
	"testing"
)

type typedResult struct {
	Step  string `json:"step"`
	Count int    `json:"count"`
}

func TestAppsMetadataUsesEmptyPermissionObjects(t *testing.T) {
	data, err := json.Marshal(Meta{UI: &AppUI{Permissions: &AppPermissions{ClipboardWrite: &AppPermission{}}}})
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != `{"ui":{"permissions":{"clipboardWrite":{}}}}` {
		t.Fatalf("metadata = %s", data)
	}
}

func TestResultMetadataPreservesAppsUI(t *testing.T) {
	original := ResultMeta{UI: &AppUI{ResourceURI: "ui://reports"}, Extensions: map[string]json.RawMessage{"example/trace": json.RawMessage(`"abc"`)}}
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatal(err)
	}
	var decoded ResultMeta
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.UI == nil || decoded.UI.ResourceURI != "ui://reports" {
		t.Fatalf("UI = %#v", decoded.UI)
	}
	if string(decoded.Extensions["example/trace"]) != `"abc"` {
		t.Fatalf("extensions = %#v", decoded.Extensions)
	}
}

func TestNewToolResultStructuredUsesTypedValue(t *testing.T) {
	result, err := NewToolResultStructured(typedResult{Step: "done", Count: 2}, "finished")
	if err != nil {
		t.Fatal(err)
	}
	var got typedResult
	if err := json.Unmarshal(result.StructuredContent, &got); err != nil {
		t.Fatal(err)
	}
	if got.Step != "done" || got.Count != 2 {
		t.Fatalf("structured result = %#v", got)
	}
	if result.ResultType != "complete" || result.Content[0].Text != "finished" {
		t.Fatalf("result = %#v", result)
	}
}

func TestNewToolResultStructuredOnlyUsesJSONFallback(t *testing.T) {
	result, err := NewToolResultStructuredOnly(typedResult{Step: "done", Count: 2})
	if err != nil {
		t.Fatal(err)
	}
	if result.Content[0].Text != `{"step":"done","count":2}` {
		t.Fatalf("text fallback = %q", result.Content[0].Text)
	}
	if result.IsError {
		t.Fatal("structured result marked as error")
	}
}
