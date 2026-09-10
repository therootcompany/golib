package geoip

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestGeoIPDB_SetPublishesManually confirms Set publishes immediately and
// reports HasValue, without touching the network.
func TestGeoIPDB_SetPublishesManually(t *testing.T) {
	f := &GeoIPDB{Dir: t.TempDir()}
	db := &Databases{} // empty but non-nil
	if err := f.Set(db); err != nil {
		t.Fatalf("Set: %v", err)
	}
	if f.Current() == nil {
		t.Fatal("Current should be non-nil after Set")
	}
	if !f.Status().HasValue {
		t.Error("Status.HasValue should be true after Set")
	}
	if f.Status().LoadedAt.IsZero() {
		t.Error("LoadedAt should be set after Set")
	}
}

// TestGeoIPDB_ClearNils confirms Clear removes the published snapshot.
func TestGeoIPDB_ClearNils(t *testing.T) {
	f := &GeoIPDB{Dir: t.TempDir()}
	if err := f.Set(&Databases{}); err != nil {
		t.Fatal(err)
	}
	if err := f.Clear(); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if f.Current() != nil {
		t.Error("Current should be nil after Clear")
	}
	if f.Status().HasValue {
		t.Error("HasValue should be false after Clear")
	}
}

// TestGeoIPDB_ClearIsIdempotent confirms repeated Clear is safe.
func TestGeoIPDB_ClearIsIdempotent(t *testing.T) {
	f := &GeoIPDB{Dir: t.TempDir()}
	for range 3 {
		if err := f.Clear(); err != nil {
			t.Fatalf("Clear: %v", err)
		}
	}
}

// TestGeoIPDB_DueWhenEmpty confirms an unloaded DB is due.
func TestGeoIPDB_DueWhenEmpty(t *testing.T) {
	f := &GeoIPDB{Dir: t.TempDir(), maxAge: 3 * 24 * time.Hour}
	due, err := f.Due(context.Background())
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	if !due {
		t.Error("empty GeoIPDB should be due")
	}
}

// TestGeoIPDB_DueGatedByMaxAge confirms that after a Set, with a future
// StaleAt (loadedAt + maxAge), Due returns false.
func TestGeoIPDB_DueGatedByMaxAge(t *testing.T) {
	f := &GeoIPDB{Dir: t.TempDir(), maxAge: 3 * 24 * time.Hour}
	if err := f.Set(&Databases{}); err != nil {
		t.Fatal(err)
	}
	due, err := f.Due(context.Background())
	if err != nil {
		t.Fatalf("Due: %v", err)
	}
	if due {
		t.Error("Due should be false immediately after Set with a future StaleAt")
	}
}

// TestGeoIPDB_KeepsLastGoodOnSetNil confirms Set(nil) clears but does not
// panic on a previously-nil snapshot.
func TestGeoIPDB_SetNilOnEmpty(t *testing.T) {
	f := &GeoIPDB{Dir: t.TempDir()}
	if err := f.Set(nil); err != nil {
		t.Fatalf("Set(nil) on empty: %v", err)
	}
	if f.Current() != nil {
		t.Error("Current should be nil after Set(nil)")
	}
}

// TestGeoIPDB_StatusLastErrorStored confirms a failed refresh surfaces its
// error in Status.LastError while keeping the last-good snapshot.
func TestGeoIPDB_StatusLastErrorStored(t *testing.T) {
	f := &GeoIPDB{Dir: t.TempDir()}
	// Seed a last-good snapshot.
	if err := f.Set(&Databases{}); err != nil {
		t.Fatal(err)
	}
	// Simulate a refresh failure by storing an error directly (update() does
	// this on fetch error).
	want := errors.New("fetch failed")
	errCopy := want
	f.lastErr.Store(&errCopy)

	status := f.Status()
	if !errors.Is(status.LastError, want) {
		t.Errorf("LastError = %v, want %v", status.LastError, want)
	}
	if !status.HasValue {
		t.Error("last-good snapshot should still be present after failure")
	}
}
