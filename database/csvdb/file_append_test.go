package csvdb

import (
	"context"
	"os"
	"testing"

	"github.com/therootcompany/golib/database/rowsync"
)

func insertPlan[T any](key string, rows ...T) rowsync.Plan[T] {
	plan := rowsync.Plan[T]{Mode: rowsync.UpdateMode}
	for i := range rows {
		row := rows[i]
		plan.Actions = append(plan.Actions, rowsync.Action[T]{Kind: rowsync.InsertAction, Key: key, After: &row})
		plan.Final = append(plan.Final, row)
	}
	return plan
}

func TestFileAppendFastPathPreservesPrefix(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &Store[testRuleRow]{Root: root, Name: "rules.tsv", Format: "tsv"}
	ctx := context.Background()
	if err := store.WriteAll(ctx, []testRuleRow{{Email: "a@example.test"}}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(dir + "/rules.tsv")
	plan := insertPlan[testRuleRow]("b@example.test", testRuleRow{Email: "b@example.test"})
	if err := store.Update(ctx, plan); err != nil {
		t.Fatal(err)
	}
	after, _ := os.ReadFile(dir + "/rules.tsv")
	if string(after[:len(before)]) != string(before) {
		t.Fatal("append fast path changed existing bytes")
	}
	rows, err := store.Fetch(ctx)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
}

func TestFileAppendHeaderMismatchFallsBackToRewrite(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &Store[testRuleRow]{Root: root, Name: "rules.tsv", Format: "tsv"}
	ctx := context.Background()

	// Create a file with a manually-written header that has fewer columns
	// than the struct produces. This simulates the production bug: a
	// template-derived TSV whose header doesn't match the encoder output.
	if err := root.WriteFile("rules.tsv", []byte("email\nold@example.test\n"), 0600); err != nil {
		t.Fatal(err)
	}

	// Insert-only plan: Update must detect the header mismatch and fall
	// back to a full atomic rewrite instead of appending mismatched rows.
	newRow := testRuleRow{Email: "new@example.test"}
	plan := insertPlan[testRuleRow]("new@example.test", newRow)
	plan.Final = []testRuleRow{
		{Email: "old@example.test"},
		newRow,
	}
	if err := store.Update(ctx, plan); err != nil {
		t.Fatalf("Update with header mismatch: %v", err)
	}

	rows, err := store.Fetch(ctx)
	if err != nil {
		t.Fatalf("Fetch after rewrite: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
}

func TestFileUpdateFallsBackToRewrite(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &Store[testRuleRow]{Root: root, Name: "rules.tsv", Format: "tsv"}
	ctx := context.Background()
	initial := []testRuleRow{{Email: "a@example.test"}}
	if err := store.WriteAll(ctx, initial); err != nil {
		t.Fatal(err)
	}
	changed := testRuleRow{Email: "changed@example.test"}
	plan := rowsync.Plan[testRuleRow]{
		Mode:  rowsync.SyncMode,
		Final: []testRuleRow{changed},
		Actions: []rowsync.Action[testRuleRow]{{
			Kind:   rowsync.UpdateAction,
			Key:    "changed@example.test",
			Before: &initial[0],
			After:  &changed,
		}},
	}
	if err := store.Update(ctx, plan); err != nil {
		t.Fatal(err)
	}
	rows, err := store.Fetch(ctx)
	if err != nil || len(rows) != 1 || rows[0].Email != "changed@example.test" {
		t.Fatalf("rows=%#v err=%v", rows, err)
	}
}

func TestFileUpdateRequiresFinalState(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &Store[testRuleRow]{Root: root, Name: "rules.tsv", Format: "tsv"}
	ctx := context.Background()
	if err := store.WriteAll(ctx, []testRuleRow{{Email: "a@example.test"}}); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(dir + "/rules.tsv")
	row := testRuleRow{Email: "a@example.test"}
	plan := rowsync.Plan[testRuleRow]{
		Actions: []rowsync.Action[testRuleRow]{{Kind: rowsync.DeleteAction, Key: "a@example.test", Before: &row}},
	}
	if err := store.Update(ctx, plan); err == nil {
		t.Fatal("Update accepted a plan without a final state")
	}
	after, _ := os.ReadFile(dir + "/rules.tsv")
	if string(before) != string(after) {
		t.Fatal("failed Update modified the file")
	}
}

func TestFileFailedWritePreservesPreviousFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root; permission bits do not apply")
	}
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &Store[testRuleRow]{Root: root, Name: "rules.tsv", Format: "tsv"}
	ctx := context.Background()
	original := []testRuleRow{{Email: "a@example.test"}}
	if err := store.WriteAll(ctx, original); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0555); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = os.Chmod(dir, 0755) }()
	row := testRuleRow{Email: "changed@example.test"}
	plan := rowsync.Plan[testRuleRow]{
		Mode:  rowsync.SyncMode,
		Final: []testRuleRow{row},
		Actions: []rowsync.Action[testRuleRow]{{
			Kind:   rowsync.UpdateAction,
			Key:    "changed@example.test",
			Before: &original[0],
			After:  &row,
		}},
	}
	if err := store.Update(ctx, plan); err == nil {
		t.Fatal("Update succeeded on a read-only directory")
	}
	rows, err := store.Fetch(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].Email != "a@example.test" {
		t.Fatalf("previous file not preserved: %#v", rows)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name() != "rules.tsv" {
		t.Fatalf("leftover temp files: %v", entries)
	}
}

func TestFileZeroActionPlanLeavesFileUnchanged(t *testing.T) {
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	store := &Store[testRuleRow]{Root: root, Name: "rules.tsv", Format: "tsv"}
	ctx := context.Background()
	if err := store.WriteAll(ctx, []testRuleRow{{Email: "a@example.test"}}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(dir + "/rules.tsv")
	if err != nil {
		t.Fatal(err)
	}
	statBefore, err := os.Stat(dir + "/rules.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Update(ctx, rowsync.Plan[testRuleRow]{Mode: rowsync.UpdateMode, Final: []testRuleRow{{Email: "a@example.test"}}}); err != nil {
		t.Fatal(err)
	}
	after, err := os.ReadFile(dir + "/rules.tsv")
	if err != nil {
		t.Fatal(err)
	}
	statAfter, err := os.Stat(dir + "/rules.tsv")
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) || !statBefore.ModTime().Equal(statAfter.ModTime()) {
		t.Fatal("zero-action plan rewrote the file")
	}
}
