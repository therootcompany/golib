package ippolicy

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
)

func TestPolicyKeepsSnapshotAfterFailedRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(t.Context(), Config{Whitelist: path})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()

	if !p.Evaluate(netip.MustParseAddr("192.0.2.1")).Whitelisted {
		t.Fatal("initial whitelist did not match")
	}
	if err := os.WriteFile(path, []byte("invalid entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := p.refresh(false); err == nil {
		t.Fatal("invalid refresh unexpectedly succeeded")
	}
	if !p.Evaluate(netip.MustParseAddr("192.0.2.1")).Whitelisted {
		t.Fatal("failed refresh replaced valid snapshot")
	}
}

func TestPolicyWhitelistPrecedesExtraBlacklist(t *testing.T) {
	dir := t.TempDir()
	white := filepath.Join(dir, "white.tsv")
	black := filepath.Join(dir, "black.tsv")
	if err := os.WriteFile(white, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(black, []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	p, err := New(context.Background(), Config{Whitelist: white, BlacklistExtra: black})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = p.Close() }()
	if p.Evaluate(netip.MustParseAddr("192.0.2.1")).Blocked {
		t.Fatal("whitelist did not take precedence")
	}
	if !p.Evaluate(netip.MustParseAddr("192.0.2.2")).Blocked {
		t.Fatal("extra blacklist did not block")
	}
}
