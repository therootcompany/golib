package rowsync

import (
	"context"
	"errors"
	"reflect"
	"testing"
)

type planRow struct {
	ID    string
	Value string
}

func rowPlanner(mode Mode) Planner[planRow] {
	return Planner[planRow]{
		Mode:  mode,
		Key:   func(row planRow) string { return row.ID },
		Equal: func(a, b planRow) bool { return a == b },
		ChangedFields: func(a, b planRow) []string {
			if a.Value != b.Value {
				return []string{"value"}
			}
			return nil
		},
	}
}

func TestPlannerBuildsDeterministicPlan(t *testing.T) {
	plan, err := rowPlanner(UpdateMode).Build([]planRow{{ID: "old", Value: "one"}}, []planRow{{ID: "new", Value: "two"}})
	if err != nil {
		t.Fatal(err)
	}
	if got, want := plan.Count(), (Counts{Inserted: 1}); got != want {
		t.Fatalf("counts = %#v, want %#v", got, want)
	}
	if got := plan.Actions[0].Key; got != "new" {
		t.Fatalf("action key = %q, want new", got)
	}
}

func TestPlannerEmitsAllActionKinds(t *testing.T) {
	previous := []planRow{
		{ID: "a", Value: "same"},
		{ID: "b", Value: "old"},
		{ID: "c", Value: "gone"},
	}
	current := []planRow{
		{ID: "a", Value: "same"},
		{ID: "b", Value: "new"},
		{ID: "d", Value: "added"},
	}
	plan, err := rowPlanner(SyncMode).Build(previous, current)
	if err != nil {
		t.Fatal(err)
	}
	want := []Action[planRow]{
		{Kind: DeleteAction, Key: "c", Before: &previous[2]},
		{Kind: UpdateAction, Key: "b", Before: &previous[1], After: &current[1], ChangedFields: []string{"value"}},
		{Kind: InsertAction, Key: "d", After: &current[2]},
	}
	if !reflect.DeepEqual(plan.Actions, want) {
		t.Fatalf("actions = %#v, want %#v", plan.Actions, want)
	}
	// Final state: b updated, c removed, d added, a untouched.
	wantFinal := []planRow{{ID: "a", Value: "same"}, {ID: "b", Value: "new"}, {ID: "d", Value: "added"}}
	if !reflect.DeepEqual(plan.Final, wantFinal) {
		t.Fatalf("final = %#v, want %#v", plan.Final, wantFinal)
	}
}

func TestPlannerUpdateModeNeverDeletes(t *testing.T) {
	plan, err := rowPlanner(UpdateMode).Build([]planRow{{ID: "keep"}}, []planRow{{ID: "add"}})
	if err != nil {
		t.Fatal(err)
	}
	if got := plan.Count().Deleted; got != 0 {
		t.Fatalf("deleted = %d, want 0", got)
	}
	// Destination-only rows survive in the final state.
	wantFinal := []planRow{{ID: "add"}, {ID: "keep"}}
	if !reflect.DeepEqual(plan.Final, wantFinal) {
		t.Fatalf("final = %#v, want %#v", plan.Final, wantFinal)
	}
}

func TestPlannerSyncModeFinalIsSourceOnly(t *testing.T) {
	plan, err := rowPlanner(SyncMode).Build([]planRow{{ID: "keep"}, {ID: "drop"}}, []planRow{{ID: "keep"}, {ID: "add"}})
	if err != nil {
		t.Fatal(err)
	}
	wantFinal := []planRow{{ID: "add"}, {ID: "keep"}}
	if !reflect.DeepEqual(plan.Final, wantFinal) {
		t.Fatalf("final = %#v, want %#v", plan.Final, wantFinal)
	}
}

func TestPlannerRejectsDuplicateKeys(t *testing.T) {
	_, err := rowPlanner(UpdateMode).Build(nil, []planRow{{ID: "x"}, {ID: "x"}})
	if err == nil {
		t.Fatal("Build accepted duplicate current keys")
	}
	_, err = rowPlanner(UpdateMode).Build([]planRow{{ID: "x"}, {ID: "x"}}, nil)
	if err == nil {
		t.Fatal("Build accepted duplicate previous keys")
	}
}

func TestPlannerRejectsEmptyKey(t *testing.T) {
	_, err := rowPlanner(UpdateMode).Build(nil, []planRow{{ID: ""}})
	if err == nil {
		t.Fatal("Build accepted an empty key")
	}
}

func TestRedactedActionsHideKeys(t *testing.T) {
	plan, err := rowPlanner(UpdateMode).Build(nil, []planRow{{ID: "private", Value: "value"}})
	if err != nil {
		t.Fatal(err)
	}
	got := plan.RedactedActions()
	if len(got) != 1 || got[0].KeyDigest == "private" || got[0].KeyDigest == "" {
		t.Fatalf("unexpected redacted action: %#v", got)
	}
}

func TestAuditRecordsDigestRowsSafely(t *testing.T) {
	previous := []planRow{{ID: "b", Value: "old"}}
	current := []planRow{{ID: "b", Value: "new"}, {ID: "d", Value: "added"}}
	plan, err := rowPlanner(SyncMode).Build(previous, current)
	if err != nil {
		t.Fatal(err)
	}
	records := plan.AuditRecords()
	if len(records) != 2 {
		t.Fatalf("records = %d, want 2", len(records))
	}
	for _, record := range records {
		if record.KeyDigest == "" || record.KeyDigest == "b" || record.KeyDigest == "d" {
			t.Fatalf("record exposes raw key: %#v", record)
		}
	}
	update := records[0]
	if update.Kind != UpdateAction || update.BeforeDigest == "" || update.AfterDigest == "" || update.BeforeDigest == update.AfterDigest {
		t.Fatalf("update record = %#v", update)
	}
	if len(update.ChangedFields) != 1 || update.ChangedFields[0] != "value" {
		t.Fatalf("changed fields = %v", update.ChangedFields)
	}
	insert := records[1]
	if insert.Kind != InsertAction || insert.BeforeDigest != "" || insert.AfterDigest == "" {
		t.Fatalf("insert record = %#v", insert)
	}
}

type planFetcher struct {
	rows  []planRow
	init  error
	fetch error
}

func (f planFetcher) Init(context.Context) ([]Message, error) { return nil, f.init }
func (f planFetcher) Fetch(context.Context) ([]planRow, error) {
	if f.fetch != nil {
		return nil, f.fetch
	}
	return f.rows, nil
}

type planUpdater struct {
	rows       []planRow
	init       error
	fetch      error
	applyErr   error
	applied    []Plan[planRow]
	lastPlan   Plan[planRow]
	updateCall int
}

func (u *planUpdater) Init(context.Context) ([]Message, error) { return nil, u.init }
func (u *planUpdater) Fetch(context.Context) ([]planRow, error) {
	if u.fetch != nil {
		return nil, u.fetch
	}
	return u.rows, nil
}
func (u *planUpdater) Update(_ context.Context, plan Plan[planRow]) error {
	u.updateCall++
	u.applied = append(u.applied, plan)
	u.lastPlan = plan
	return u.applyErr
}

func TestBuildMergedPlanPreservesDestinationRows(t *testing.T) {
	updater := &planUpdater{rows: []planRow{{ID: "keep", Value: "old"}}}
	result, err := BuildMergedPlan(
		context.Background(),
		planFetcher{rows: []planRow{{ID: "new", Value: "new"}}},
		updater,
		rowPlanner(UpdateMode),
		func(previous, source []planRow) ([]planRow, error) {
			return append(append([]planRow(nil), previous...), source...), nil
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Plan.Count().Inserted; got != 1 {
		t.Fatalf("inserted = %d, want 1", got)
	}
}

func TestBuildPlanDoesNotApply(t *testing.T) {
	updater := &planUpdater{rows: []planRow{{ID: "old"}}}
	result, err := BuildPlan(context.Background(), planFetcher{rows: []planRow{{ID: "new"}}}, updater, rowPlanner(UpdateMode))
	if err != nil {
		t.Fatal(err)
	}
	if len(updater.applied) != 0 {
		t.Fatal("BuildPlan applied changes")
	}
	if !reflect.DeepEqual(result.Plan.Final, []planRow{{ID: "new"}, {ID: "old"}}) {
		t.Fatalf("unexpected final plan: %#v", result.Plan.Final)
	}
}

func TestPlannerRejectsEmptySource(t *testing.T) {
	_, err := rowPlanner(SyncMode).Build([]planRow{{ID: "existing"}}, nil)
	if err == nil {
		t.Fatal("Build accepted an empty source")
	}
}

func TestRunStoreAppliesPlanOnce(t *testing.T) {
	output := &planUpdater{rows: []planRow{{ID: "old", Value: "one"}}}
	result, err := RunStore(context.Background(), planFetcher{rows: []planRow{{ID: "new", Value: "two"}}}, output, rowPlanner(SyncMode))
	if err != nil {
		t.Fatal(err)
	}
	if len(output.applied) != 1 {
		t.Fatalf("applied %d plans, want 1", len(output.applied))
	}
	if got := result.Plan.Count(); got.Inserted != 1 || got.Deleted != 1 {
		t.Fatalf("counts = %#v", got)
	}
	// Re-run: destination now matches source, zero actions, no second apply needed.
	output.rows = []planRow{{ID: "new", Value: "two"}}
	result2, err := RunStore(context.Background(), planFetcher{rows: []planRow{{ID: "new", Value: "two"}}}, output, rowPlanner(SyncMode))
	if err != nil {
		t.Fatal(err)
	}
	if got := result2.Plan.Count(); got != (Counts{}) {
		t.Fatalf("second run counts = %#v, want none", got)
	}
}

func TestRunStoreRejectsEmptySourceWithRows(t *testing.T) {
	output := &planUpdater{rows: []planRow{{ID: "existing"}}}
	_, err := RunStore(context.Background(), planFetcher{rows: nil}, output, rowPlanner(SyncMode))
	if err == nil {
		t.Fatal("RunStore accepted an empty source over a populated destination")
	}
	if output.updateCall != 0 {
		t.Fatal("destination was modified before the empty source was rejected")
	}
}

func TestRunStoreEmptyBothSidesIsNoOp(t *testing.T) {
	output := &planUpdater{}
	result, err := RunStore(context.Background(), planFetcher{rows: nil}, output, rowPlanner(SyncMode))
	if err != nil {
		t.Fatal(err)
	}
	if output.updateCall != 0 || len(result.Plan.Actions) != 0 {
		t.Fatalf("expected no-op, got call=%d actions=%d", output.updateCall, len(result.Plan.Actions))
	}
}

func TestRunStoreFetchErrorLeavesDestinationUntouched(t *testing.T) {
	output := &planUpdater{rows: []planRow{{ID: "keep"}}}
	boom := errors.New("source unavailable")
	_, err := RunStore(context.Background(), planFetcher{rows: nil, fetch: boom}, output, rowPlanner(SyncMode))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	if output.updateCall != 0 {
		t.Fatal("destination was modified after a source fetch error")
	}
	_, err = RunStore(context.Background(), planFetcher{rows: nil}, &planUpdater{fetch: boom}, rowPlanner(SyncMode))
	if err == nil {
		t.Fatal("RunStore accepted a destination fetch error")
	}
}

type invalidFetcher struct {
	rows        []planRow
	invalid     int
	invalidRows []int
}

func (f invalidFetcher) Init(context.Context) ([]Message, error)  { return nil, nil }
func (f invalidFetcher) Fetch(context.Context) ([]planRow, error) { return f.rows, nil }
func (f invalidFetcher) InvalidCount() int                        { return f.invalid }
func (f invalidFetcher) InvalidRows() []int                       { return f.invalidRows }

func TestRunStoreReportsInvalidRows(t *testing.T) {
	result, err := RunStore(context.Background(),
		invalidFetcher{rows: []planRow{{ID: "a"}}, invalid: 2, invalidRows: []int{3, 7}},
		&planUpdater{}, rowPlanner(UpdateMode))
	if err != nil {
		t.Fatal(err)
	}
	if result.Invalid != 2 || len(result.InvalidRows) != 2 || result.InvalidRows[0] != 3 {
		t.Fatalf("invalid = %d %v", result.Invalid, result.InvalidRows)
	}
}

func TestRunStoreRetryAfterFailedApplyIsSafe(t *testing.T) {
	boom := errors.New("apply failed")
	// First attempt: apply fails midway; destination is untouched.
	first := &planUpdater{rows: []planRow{{ID: "old"}}, applyErr: boom}
	_, err := RunStore(context.Background(), planFetcher{rows: []planRow{{ID: "new"}}}, first, rowPlanner(SyncMode))
	if !errors.Is(err, boom) {
		t.Fatalf("err = %v, want %v", err, boom)
	}
	// Retry: a fresh run from the same source produces the identical plan and
	// applies successfully to the same final state.
	second := &planUpdater{rows: []planRow{{ID: "old"}}}
	result, err := RunStore(context.Background(), planFetcher{rows: []planRow{{ID: "new"}}}, second, rowPlanner(SyncMode))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(result.Plan.Final, []planRow{{ID: "new"}}) {
		t.Fatalf("retry final = %#v", result.Plan.Final)
	}
	if len(second.applied) != 1 {
		t.Fatalf("retry applied %d plans", len(second.applied))
	}
}

func TestRunMergedStoreForcesUpdateMode(t *testing.T) {
	// Even a SyncMode planner must not delete through a merged pipeline.
	output := &planUpdater{rows: []planRow{{ID: "dest-only"}}}
	result, err := RunMergedStore(context.Background(),
		planFetcher{rows: []planRow{{ID: "src-only"}}},
		output,
		func(previous, source []planRow) ([]planRow, error) {
			return append(append([]planRow(nil), previous...), source...), nil
		},
		rowPlanner(SyncMode))
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Plan.Count().Deleted; got != 0 {
		t.Fatalf("merged pipeline deleted %d rows", got)
	}
	if result.Plan.Mode != UpdateMode {
		t.Fatalf("mode = %v, want UpdateMode", result.Plan.Mode)
	}
	if output.lastPlan.Mode != UpdateMode {
		t.Fatalf("applied plan mode = %v, want UpdateMode", output.lastPlan.Mode)
	}
}

func TestRunMergedStoreEmptySourceKeepsDestination(t *testing.T) {
	output := &planUpdater{rows: []planRow{{ID: "keep"}}}
	result, err := RunMergedStore(context.Background(),
		planFetcher{rows: nil},
		output,
		func(previous, source []planRow) ([]planRow, error) {
			return append(append([]planRow(nil), previous...), source...), nil
		},
		rowPlanner(SyncMode))
	if err != nil {
		t.Fatal(err)
	}
	if got := result.Plan.Count(); got != (Counts{}) {
		t.Fatalf("counts = %#v, want none", got)
	}
}
