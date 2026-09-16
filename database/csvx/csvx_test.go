package csvx

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestUUIDRoundtrip(t *testing.T) {
	// Valid UUID
	u := UUID{Bytes: [16]byte(uuid.New()), Valid: true}

	// CSV roundtrip
	data, err := u.MarshalCSV()
	if err != nil {
		t.Fatalf("MarshalCSV: %v", err)
	}
	var u2 UUID
	if err := u2.UnmarshalCSV(data); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if u2.String() != u.String() {
		t.Fatalf("CSV roundtrip mismatch: %s != %s", u2.String(), u.String())
	}

	// Nil UUID
	var nilU UUID
	data, err = nilU.MarshalCSV()
	if err != nil {
		t.Fatalf("MarshalCSV nil: %v", err)
	}
	if data != nil {
		t.Fatalf("expected nil for invalid UUID, got %v", data)
	}
	var nilU2 UUID
	if err := nilU2.UnmarshalCSV(nil); err != nil {
		t.Fatalf("UnmarshalCSV nil: %v", err)
	}
	if nilU2.Valid {
		t.Fatal("expected invalid after nil unmarshal")
	}

	// driver.Value roundtrip
	v, err := u.Value()
	if err != nil {
		t.Fatalf("Value: %v", err)
	}
	if s, ok := v.(string); !ok || s != u.String() {
		t.Fatalf("Value returned %T %v, want string %s", v, v, u.String())
	}

	// Scan from string
	var scanned UUID
	if err := scanned.Scan(u.String()); err != nil {
		t.Fatalf("Scan string: %v", err)
	}
	if scanned.String() != u.String() {
		t.Fatalf("Scan mismatch: %s != %s", scanned.String(), u.String())
	}

	// Scan from nil
	if err := scanned.Scan(nil); err != nil {
		t.Fatalf("Scan nil: %v", err)
	}
	if scanned.Valid {
		t.Fatal("expected invalid after Scan(nil)")
	}
}

func TestTextRoundtrip(t *testing.T) {
	tt := Text{String: "hello", Valid: true}

	data, err := tt.MarshalCSV()
	if err != nil {
		t.Fatalf("MarshalCSV: %v", err)
	}
	if string(data) != "hello" {
		t.Fatalf("MarshalCSV: got %q", data)
	}
	var tt2 Text
	if err := tt2.UnmarshalCSV(data); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if tt2.String != "hello" || !tt2.Valid {
		t.Fatalf("UnmarshalCSV: got %+v", tt2)
	}

	// Nil
	var nilT Text
	data, _ = nilT.MarshalCSV()
	if data != nil {
		t.Fatalf("expected nil, got %v", data)
	}

	// driver.Value
	v, _ := tt.Value()
	if v != "hello" {
		t.Fatalf("Value: got %v", v)
	}
}

func TestTimestampRoundtrip(t *testing.T) {
	now := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	ts := Timestamp{Time: now, Valid: true}

	data, err := ts.MarshalCSV()
	if err != nil {
		t.Fatalf("MarshalCSV: %v", err)
	}
	var ts2 Timestamp
	if err := ts2.UnmarshalCSV(data); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if !ts2.Time.Equal(now) {
		t.Fatalf("roundtrip: %s != %s", ts2.Time, now)
	}

	// driver.Value returns time.Time
	v, _ := ts.Value()
	if v != now {
		t.Fatalf("Value: got %T %v", v, v)
	}

	// Scan from time.Time
	var scanned Timestamp
	if err := scanned.Scan(now); err != nil {
		t.Fatalf("Scan time.Time: %v", err)
	}
	if !scanned.Time.Equal(now) || !scanned.Valid {
		t.Fatalf("Scan: got %+v", scanned)
	}
}

func TestTimestamptzRoundtrip(t *testing.T) {
	now := time.Date(2025, 6, 20, 14, 0, 0, 0, time.UTC)
	tz := Timestamptz{Time: now, Valid: true}

	data, err := tz.MarshalCSV()
	if err != nil {
		t.Fatalf("MarshalCSV: %v", err)
	}
	var tz2 Timestamptz
	if err := tz2.UnmarshalCSV(data); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if !tz2.Time.Equal(now) {
		t.Fatalf("roundtrip: %s != %s", tz2.Time, now)
	}
}

func TestDateRoundtrip(t *testing.T) {
	d := Date{Time: time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC), Valid: true}

	data, err := d.MarshalCSV()
	if err != nil {
		t.Fatalf("MarshalCSV: %v", err)
	}
	if string(data) != "2025-03-15" {
		t.Fatalf("MarshalCSV: got %q", data)
	}
	var d2 Date
	if err := d2.UnmarshalCSV(data); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if d2.Time.Day() != 15 || d2.Time.Month() != 3 || d2.Time.Year() != 2025 {
		t.Fatalf("UnmarshalCSV: got %s", d2.Time)
	}
}

func TestBoolRoundtrip(t *testing.T) {
	b := Bool{Bool: true, Valid: true}

	data, err := b.MarshalCSV()
	if err != nil {
		t.Fatalf("MarshalCSV: %v", err)
	}
	if string(data) != "true" {
		t.Fatalf("MarshalCSV: got %q", data)
	}
	var b2 Bool
	if err := b2.UnmarshalCSV(data); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if !b2.Bool || !b2.Valid {
		t.Fatalf("UnmarshalCSV: got %+v", b2)
	}

	// driver.Value
	v, _ := b.Value()
	if v != true {
		t.Fatalf("Value: got %v", v)
	}
}

func TestBoolishTimestamp(t *testing.T) {
	// True-like
	var v BoolishTimestamp
	if err := v.UnmarshalCSV([]byte("true")); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if !v.Valid || !v.Bool {
		t.Fatalf("expected valid+true, got %+v", v)
	}

	// False-like
	if err := v.UnmarshalCSV([]byte("no")); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if !v.Valid || v.Bool {
		t.Fatalf("expected valid+false, got %+v", v)
	}

	// Empty
	if err := v.UnmarshalCSV([]byte("")); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if v.Valid {
		t.Fatal("expected invalid for empty")
	}

	// Timestamp
	if err := v.UnmarshalCSV([]byte("2025-01-15")); err != nil {
		t.Fatalf("UnmarshalCSV: %v", err)
	}
	if !v.Valid || !v.Bool || v.Timestamp.IsZero() {
		t.Fatalf("expected valid+true+timestamp, got %+v", v)
	}
}
