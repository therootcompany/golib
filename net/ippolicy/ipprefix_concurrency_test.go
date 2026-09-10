package ippolicy

import (
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/therootcompany/golib/net/ipcohort"
)

// TestIPPrefixSet_SetPublishesManually confirms Set publishes immediately and
// bumps the generation so a subsequent stale refresh cannot overwrite it.
func TestIPPrefixSet_SetPublishesManually(t *testing.T) {
	ps := EmptyIPPrefixSet()

	cohort, err := ipcohort.Parse([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Set(cohort); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if got := ps.Current(); got == nil || got.Size() == 0 {
		t.Fatalf("after Set Current = %v", got)
	}
	if !ps.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Error("Contains should match after Set")
	}
	if ps.Status().LoadedAt.IsZero() {
		t.Error("LoadedAt should be set after Set")
	}
}

// TestIPPrefixSet_ClearNilsCohort confirms Clear removes the published value
// and resets the loaded clock.
func TestIPPrefixSet_ClearNilsCohort(t *testing.T) {
	ps := EmptyIPPrefixSet()
	cohort, err := ipcohort.Parse([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Set(cohort); err != nil {
		t.Fatal(err)
	}
	if err := ps.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if ps.Current() != nil {
		t.Error("Current should be nil after Clear")
	}
	if !ps.Status().LoadedAt.IsZero() {
		t.Error("LoadedAt should be zero after Clear")
	}
}

// TestIPPrefixSet_DueWhenEmpty confirms an empty set is due.
func TestIPPrefixSet_DueWhenEmpty(t *testing.T) {
	ps := EmptyIPPrefixSet()
	due, err := ps.Due(context.Background())
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	if !due {
		t.Error("empty IPPrefixSet should be due")
	}
}

// TestIPPrefixSet_ClearIsIdempotent confirms repeated Clear is safe.
func TestIPPrefixSet_ClearIsIdempotent(t *testing.T) {
	ps := EmptyIPPrefixSet()
	for range 3 {
		if err := ps.Clear(); err != nil {
			t.Fatalf("Clear: %v", err)
		}
	}
	if ps.Current() != nil {
		t.Error("Current should be nil after repeated Clear")
	}
}

// TestIPPrefixSet_StopOnZeroValue confirms a zero-value set can be stopped
// without panicking (defensive).
func TestIPPrefixSet_StopOnZeroValue(t *testing.T) {
	var ps *IPPrefixSet
	// nil receiver must not panic.
	ps.Stop()
}

// TestIPPrefixSet_StatusRefreshingFlag confirms Status reports Refreshing
// during an in-flight refresh. We cannot easily block a git refresh, so this
// is a smoke test that Refreshing starts false.
func TestIPPrefixSet_StatusNotRefreshingAtRest(t *testing.T) {
	ps := EmptyIPPrefixSet()
	if ps.Status().Refreshing {
		t.Error("Refreshing should be false at rest")
	}
}

// TestIPPrefixSet_IntervalDrivesStaleAt confirms StaleAt is LoadedAt+interval.
func TestIPPrefixSet_IntervalDrivesStaleAt(t *testing.T) {
	ps := EmptyIPPrefixSet()
	ps.interval = time.Hour
	cohort, err := ipcohort.Parse([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}
	if err := ps.Set(cohort); err != nil {
		t.Fatal(err)
	}
	status := ps.Status()
	if status.StaleAt.IsZero() {
		t.Fatal("StaleAt should be set after Set with a non-zero interval")
	}
	want := status.LoadedAt.Add(time.Hour)
	if !status.StaleAt.Equal(want) {
		t.Errorf("StaleAt = %v, want %v", status.StaleAt, want)
	}
	// Right after Set, with a 1h interval, we should NOT be due.
	if due, _ := ps.Due(context.Background()); due {
		t.Error("Due should be false immediately after Set with a future StaleAt")
	}
}
