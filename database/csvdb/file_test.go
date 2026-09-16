package csvdb

import (
	"context"
	"os"
	"testing"

	"github.com/therootcompany/golib/database/csvx"
)

func TestFileRoundtrip(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f := &Store[testRuleRow]{Root: root, Name: "test.tsv", Format: "tsv"}
	ctx := context.Background()

	if _, err := f.Init(ctx); err != nil {
		t.Fatal(err)
	}
	rows := []testRuleRow{
		{Email: "a@example.com"},
		{Email: "b@example.com"},
	}
	if err := f.WriteAll(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, err := f.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("got %d rows, want 2", len(got))
	}
	if got[0].Email != "a@example.com" || got[1].Email != "b@example.com" {
		t.Fatalf("unexpected rows: %v", got)
	}
}

func TestFileNormalizeHook(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f := &Store[identityRow]{
		Root:   root,
		Name:   "identities.tsv",
		Format: "tsv",
		Normalize: func(rows []identityRow) {
			for i := range rows {
				if rows[i].Email.Valid {
					rows[i].Email.String = csvx.NormalizeEmail(rows[i].Email.String)
				}
				if rows[i].Phone.Valid {
					rows[i].Phone.String = csvx.NormalizePhone(rows[i].Phone.String)
				}
			}
		},
	}
	ctx := context.Background()
	rows := []identityRow{{
		Email: csvx.Text{String: " USER@Example.COM ", Valid: true},
		Phone: csvx.Text{String: "+1 (415) 555-0123", Valid: true},
	}}
	if err := f.WriteAll(ctx, rows); err != nil {
		t.Fatal(err)
	}
	got, err := f.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Email.String != "user@example.com" || got[0].Phone.String != "(415) 555-0123" {
		t.Fatalf("contacts = %#v", got)
	}
}

func TestFileFetchSkipsComments(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	content := "# beginner note\nemail\trevoked_at\texpires_at\nuser@example.com\t\t\n"
	if err := root.WriteFile("comments.tsv", []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	f := &Store[testRuleRow]{Root: root, Name: "comments.tsv", Format: "tsv"}
	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Email != "user@example.com" {
		t.Fatalf("got %#v, want one parsed row", got)
	}
}

func TestFileFetchMissing(t *testing.T) {
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f := &Store[testRuleRow]{Root: root, Name: "missing.tsv", Format: "tsv"}
	got, err := f.Fetch(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("got %d rows, want 0", len(got))
	}
}

func TestFileAtomicWrite(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	f := &Store[testRuleRow]{Root: root, Name: "test.tsv", Format: "tsv"}
	ctx := context.Background()
	if _, err := f.Init(ctx); err != nil {
		t.Fatal(err)
	}
	rows := []testRuleRow{{Email: "x@example.com"}}
	for range 5 {
		if err := f.WriteAll(ctx, rows); err != nil {
			t.Fatal(err)
		}
	}
	info, err := root.Stat("test.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("file is empty after writes")
	}
	entries, _ := os.ReadDir(dir)
	if len(entries) != 1 {
		t.Fatalf("expected 1 file in dir, got %d (temp files not cleaned up?)", len(entries))
	}
}
