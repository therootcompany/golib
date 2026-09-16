package rowsync

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"maps"
	"sort"
)

// Mode controls whether a plan may delete destination rows.
type Mode uint8

const (
	// UpdateMode inserts and updates rows but never deletes destination rows.
	UpdateMode Mode = iota
	// SyncMode makes the source authoritative and includes deletes.
	SyncMode
)

// ActionKind identifies one planned destination action.
type ActionKind uint8

const (
	InsertAction ActionKind = iota
	UpdateAction
	DeleteAction
)

// Action is one deterministic change to apply.
type Action[T any] struct {
	Kind          ActionKind
	Key           string
	Before        *T
	After         *T
	ChangedFields []string
}

// Plan is the complete result of comparing source and destination rows.
type Plan[T any] struct {
	Mode     Mode
	Previous []T
	Current  []T
	Final    []T
	Actions  []Action[T]
}

// Counts summarizes planned actions.
type Counts struct {
	Inserted int
	Updated  int
	Deleted  int
}

// Count returns the number of actions by kind.
func (p Plan[T]) Count() Counts {
	var counts Counts
	for _, action := range p.Actions {
		switch action.Kind {
		case InsertAction:
			counts.Inserted++
		case UpdateAction:
			counts.Updated++
		case DeleteAction:
			counts.Deleted++
		}
	}
	return counts
}

// ActionSummary is safe for audit output. It never contains the source key.
type ActionSummary struct {
	Kind          ActionKind
	KeyDigest     string
	ChangedFields []string
}

// AuditRecord maps one plan action to safe audit metadata: action kind, key
// digest, changed fields, and digests of the complete old and new rows. Raw
// row data (which may hold secrets, tokens, or authorization codes) is never
// exposed; consumers needing full rows hold the plan itself.
type AuditRecord struct {
	Kind          ActionKind
	KeyDigest     string
	ChangedFields []string
	BeforeDigest  string // sha256 of the complete previous row; "" for inserts
	AfterDigest   string // sha256 of the complete new row; "" for deletes
}

// AuditRecords returns one safe audit record per planned action, in plan
// order. Row digests are stable for value-type rows within a build.
func (p Plan[T]) AuditRecords() []AuditRecord {
	result := make([]AuditRecord, 0, len(p.Actions))
	for _, action := range p.Actions {
		digest := sha256.Sum256([]byte(action.Key))
		record := AuditRecord{
			Kind:          action.Kind,
			KeyDigest:     hex.EncodeToString(digest[:6]),
			ChangedFields: append([]string(nil), action.ChangedFields...),
		}
		if action.Before != nil {
			record.BeforeDigest = rowDigest(*action.Before)
		}
		if action.After != nil {
			record.AfterDigest = rowDigest(*action.After)
		}
		result = append(result, record)
	}
	return result
}

func rowDigest[T any](row T) string {
	digest := sha256.Sum256(fmt.Append(nil, row))
	return hex.EncodeToString(digest[:])
}

// RedactedActions returns deterministic action metadata without exposing keys.
func (p Plan[T]) RedactedActions() []ActionSummary {
	result := make([]ActionSummary, 0, len(p.Actions))
	for _, action := range p.Actions {
		digest := sha256.Sum256([]byte(action.Key))
		result = append(result, ActionSummary{
			Kind:          action.Kind,
			KeyDigest:     hex.EncodeToString(digest[:6]),
			ChangedFields: append([]string(nil), action.ChangedFields...),
		})
	}
	return result
}

// Planner compares rows by a stable key.
type Planner[T any] struct {
	Mode          Mode
	Key           func(T) string
	Equal         func(T, T) bool
	ChangedFields func(T, T) []string
}

// Build creates a deterministic action plan. Empty or duplicate keys fail.
func (p Planner[T]) Build(previous, current []T) (Plan[T], error) {
	if len(current) == 0 {
		return Plan[T]{}, fmt.Errorf("source returned zero rows")
	}
	if p.Key == nil {
		return Plan[T]{}, fmt.Errorf("key function is required")
	}
	if p.Equal == nil {
		return Plan[T]{}, fmt.Errorf("equal function is required")
	}
	before, err := indexRows(previous, p.Key)
	if err != nil {
		return Plan[T]{}, fmt.Errorf("index previous rows: %w", err)
	}
	after, err := indexRows(current, p.Key)
	if err != nil {
		return Plan[T]{}, fmt.Errorf("index current rows: %w", err)
	}
	keys := make([]string, 0, len(before)+len(after))
	seen := make(map[string]struct{}, len(before)+len(after))
	for key := range before {
		seen[key] = struct{}{}
		keys = append(keys, key)
	}
	for key := range after {
		if _, ok := seen[key]; !ok {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)

	plan := Plan[T]{Mode: p.Mode, Previous: append([]T(nil), previous...), Current: append([]T(nil), current...)}
	final := make(map[string]T, len(before)+len(after))
	maps.Copy(final, before)
	maps.Copy(final, after)
	if p.Mode == SyncMode {
		for key := range before {
			if _, ok := after[key]; !ok {
				delete(final, key)
			}
		}
	}
	for _, key := range keys {
		oldRow, hadOld := before[key]
		newRow, hasNew := after[key]
		switch {
		case !hadOld && hasNew:
			row := newRow
			plan.Actions = append(plan.Actions, Action[T]{Kind: InsertAction, Key: key, After: &row})
		case hadOld && !hasNew && p.Mode == SyncMode:
			row := oldRow
			plan.Actions = append(plan.Actions, Action[T]{Kind: DeleteAction, Key: key, Before: &row})
		case hadOld && hasNew && !p.Equal(oldRow, newRow):
			oldCopy, newCopy := oldRow, newRow
			action := Action[T]{Kind: UpdateAction, Key: key, Before: &oldCopy, After: &newCopy}
			if p.ChangedFields != nil {
				action.ChangedFields = append([]string(nil), p.ChangedFields(oldRow, newRow)...)
			}
			plan.Actions = append(plan.Actions, action)
		}
	}
	sort.Slice(plan.Actions, func(i, j int) bool {
		left, right := plan.Actions[i], plan.Actions[j]
		if actionOrder(left.Kind) != actionOrder(right.Kind) {
			return actionOrder(left.Kind) < actionOrder(right.Kind)
		}
		return left.Key < right.Key
	})

	finalKeys := make([]string, 0, len(final))
	for key := range final {
		finalKeys = append(finalKeys, key)
	}
	sort.Strings(finalKeys)
	plan.Final = make([]T, 0, len(finalKeys))
	for _, key := range finalKeys {
		plan.Final = append(plan.Final, final[key])
	}
	return plan, nil
}

func actionOrder(kind ActionKind) int {
	switch kind {
	case DeleteAction:
		return 0
	case UpdateAction:
		return 1
	case InsertAction:
		return 2
	default:
		return 3
	}
}

func indexRows[T any](rows []T, keyFunc func(T) string) (map[string]T, error) {
	indexed := make(map[string]T, len(rows))
	for _, row := range rows {
		key := keyFunc(row)
		if key == "" {
			return nil, fmt.Errorf("row has empty key")
		}
		if _, exists := indexed[key]; exists {
			return nil, fmt.Errorf("duplicate key %q", key)
		}
		indexed[key] = row
	}
	return indexed, nil
}

// PlanResult contains source rows and the unapplied plan.
type PlanResult[T any] struct {
	Source []T
	Plan   Plan[T]
}

// BuildPlan fetches source and destination rows and builds one plan.
// It does not apply the plan.
func BuildPlan[T any](ctx context.Context, input Fetcher[T], output Fetcher[T], planner Planner[T]) (PlanResult[T], error) {
	return buildPlan(ctx, input, output, planner, nil)
}

// BuildMergedPlan is BuildPlan with an explicit merge step for partial input.
func BuildMergedPlan[T any](
	ctx context.Context,
	input Fetcher[T],
	output Fetcher[T],
	planner Planner[T],
	merge Merge[T],
) (PlanResult[T], error) {
	if merge == nil {
		return PlanResult[T]{}, fmt.Errorf("merge function is required")
	}
	return buildPlan(ctx, input, output, planner, merge)
}

func buildPlan[T any](
	ctx context.Context,
	input Fetcher[T],
	output Fetcher[T],
	planner Planner[T],
	merge Merge[T],
) (PlanResult[T], error) {
	if input == nil {
		return PlanResult[T]{}, fmt.Errorf("input fetcher is required")
	}
	if output == nil {
		return PlanResult[T]{}, fmt.Errorf("output updater is required")
	}
	if _, err := input.Init(ctx); err != nil {
		return PlanResult[T]{}, fmt.Errorf("init input: %w", err)
	}
	if _, err := output.Init(ctx); err != nil {
		return PlanResult[T]{}, fmt.Errorf("init output: %w", err)
	}
	source, err := input.Fetch(ctx)
	if err != nil {
		return PlanResult[T]{}, fmt.Errorf("fetch input: %w", err)
	}
	previous, err := output.Fetch(ctx)
	if err != nil {
		return PlanResult[T]{}, fmt.Errorf("fetch output: %w", err)
	}
	current := source
	if merge != nil {
		current, err = merge(previous, source)
		if err != nil {
			return PlanResult[T]{}, fmt.Errorf("merge: %w", err)
		}
	}
	if len(current) == 0 && len(previous) == 0 {
		return PlanResult[T]{Source: source, Plan: Plan[T]{Mode: planner.Mode}}, nil
	}
	plan, err := planner.Build(previous, current)
	if err != nil {
		return PlanResult[T]{}, fmt.Errorf("build plan: %w", err)
	}
	return PlanResult[T]{Source: source, Plan: plan}, nil
}
