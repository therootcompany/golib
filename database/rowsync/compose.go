package rowsync

import (
	"context"
	"fmt"
)

// RunStore executes the fetch → plan → apply pipeline. The planner's Mode is
// the explicit operation choice: UpdateMode is insert-update only, SyncMode
// makes the source authoritative and deletes destination rows the source
// lacks. An empty source is rejected before planning unless the destination
// is also empty, in which case the run is a no-op.
func RunStore[T any](
	ctx context.Context,
	input Fetcher[T],
	output Updater[T],
	planner Planner[T],
) (Result[T], error) {
	return runPipeline(ctx, input, output, planner, nil)
}

// RunMergedStore is RunStore with an explicit merge step for partial
// sources. The planner is forced to UpdateMode: a partial (merged) source is
// never authoritative, so destination rows the source lacks survive.
func RunMergedStore[T any](
	ctx context.Context,
	input Fetcher[T],
	output Updater[T],
	merge Merge[T],
	planner Planner[T],
) (Result[T], error) {
	if merge == nil {
		return Result[T]{}, fmt.Errorf("merge function is required")
	}
	planner.Mode = UpdateMode
	return runPipeline(ctx, input, output, planner, merge)
}

func runPipeline[T any](
	ctx context.Context,
	input Fetcher[T],
	output Updater[T],
	planner Planner[T],
	merge Merge[T],
) (Result[T], error) {
	if input == nil {
		return Result[T]{}, fmt.Errorf("input fetcher is required")
	}
	if output == nil {
		return Result[T]{}, fmt.Errorf("output updater is required")
	}
	if planner.Key == nil || planner.Equal == nil {
		return Result[T]{}, fmt.Errorf("planner key and equal functions are required")
	}
	if _, err := input.Init(ctx); err != nil {
		return Result[T]{}, fmt.Errorf("init input: %w", err)
	}
	if _, err := output.Init(ctx); err != nil {
		return Result[T]{}, fmt.Errorf("init output: %w", err)
	}
	source, err := input.Fetch(ctx)
	if err != nil {
		return Result[T]{}, fmt.Errorf("fetch input: %w", err)
	}
	previous, err := output.Fetch(ctx)
	if err != nil {
		return Result[T]{}, fmt.Errorf("fetch output: %w", err)
	}
	result := Result[T]{Source: source}
	if reporter, ok := input.(InvalidReporter); ok {
		result.Invalid = reporter.InvalidCount()
	}
	if reporter, ok := input.(InvalidRowReporter); ok {
		result.InvalidRows = reporter.InvalidRows()
	}
	current := source
	if merge != nil {
		current, err = merge(previous, source)
		if err != nil {
			return Result[T]{}, fmt.Errorf("merge: %w", err)
		}
	}
	if len(current) == 0 && len(previous) == 0 {
		// Both sides empty: nothing to plan or apply.
		result.Plan = Plan[T]{Mode: planner.Mode}
		return result, nil
	}
	plan, err := planner.Build(previous, current)
	if err != nil {
		return Result[T]{}, fmt.Errorf("build plan: %w", err)
	}
	if err := output.Update(ctx, plan); err != nil {
		return Result[T]{}, fmt.Errorf("apply plan: %w", err)
	}
	result.Plan = plan
	return result, nil
}
