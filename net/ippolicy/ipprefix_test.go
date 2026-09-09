package ippolicy

import (
	"net/netip"
	"testing"
)

func TestPrefixSetContainsZeroValue(t *testing.T) {
	var ps PrefixSet
	if ps.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("zero-value PrefixSet must not contain an address")
	}
}

func TestEmptyPrefixSet(t *testing.T) {
	ps := EmptyPrefixSet()
	defer func() { _ = ps.Close() }()

	if !ps.Loaded() {
		t.Fatal("empty prefix set should be ready")
	}
	if ps.Size() != 0 {
		t.Fatalf("size = %d, want 0", ps.Size())
	}
	if ps.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("empty prefix set contains an address")
	}
}
