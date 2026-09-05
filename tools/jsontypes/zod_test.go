package jsontypes

import (
	"strings"
	"testing"
)

func TestGenerateZodFlat(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".age{int}",
		".active{bool}",
	}
	out := GenerateZod(paths)
	assertContainsAll(t, out,
		`import { z } from "zod";`,
		"export const RootSchema = z.object({",
		"name: z.string(),",
		"age: z.number().int(),",
		"active: z.boolean(),",
		"export type Root = z.infer<typeof RootSchema>;",
	)
}

func TestGenerateZodOptional(t *testing.T) {
	paths := []string{
		"{Root}",
		".name{string}",
		".bio{string?}",
	}
	out := GenerateZod(paths)
	assertContainsAll(t, out,
		"name: z.string(),",
		"bio: z.string().nullable().optional(),",
	)
}

func TestGenerateZodNested(t *testing.T) {
	paths := []string{
		"{Root}",
		".addr{Address}",
		".addr.city{string}",
	}
	out := GenerateZod(paths)
	assertContainsAll(t, out,
		"export const AddressSchema = z.object({",
		"addr: AddressSchema,",
	)
	// AddressSchema should appear before RootSchema
	addrIdx := strings.Index(out, "AddressSchema = z.object")
	rootIdx := strings.Index(out, "RootSchema = z.object")
	if addrIdx < 0 || rootIdx < 0 || addrIdx > rootIdx {
		t.Errorf("AddressSchema should be defined before RootSchema\n%s", out)
	}
}

func TestGenerateZodArray(t *testing.T) {
	paths := []string{
		"{Root}",
		".items[]{Item}",
		".items[].id{string}",
	}
	out := GenerateZod(paths)
	assertContainsAll(t, out,
		"items: z.array(ItemSchema),",
	)
}

func TestGenerateZodMap(t *testing.T) {
	paths := []string{
		"{Root}",
		".scores[string]{Score}",
		".scores[string].value{int}",
	}
	out := GenerateZod(paths)
	assertContainsAll(t, out,
		"scores: z.record(z.string(), ScoreSchema),",
	)
}

func TestGenerateZodEmpty(t *testing.T) {
	out := GenerateZod(nil)
	if out != "" {
		t.Errorf("expected empty output, got %q", out)
	}
}

func TestGenerateZodEndToEnd(t *testing.T) {
	jsonStr := `{"name":"Alice","age":30,"tags":["a"],"meta":{"key":"val"}}`
	paths := analyzeAndFormat(t, jsonStr)
	out := GenerateZod(paths)
	assertContainsAll(t, out,
		"z.object({",
		"z.string()",
		"z.number()",
	)
}
