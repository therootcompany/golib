package mcptypes

import (
	"encoding/json"
	"testing"
)

type typedResult struct {
	Step  string `json:"step"`
	Count int    `json:"count"`
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
