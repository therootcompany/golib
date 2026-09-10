package ippolicy

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/therootcompany/golib/net/iplist"
)

func TestEnumStrings(t *testing.T) {
	for _, test := range []struct {
		value Decision
		want  string
	}{
		{Blacklisted, "blacklisted"},
		{Unlisted, "unlisted"},
		{Whitelisted, "whitelisted"},
		{Decision(99), "decision(99)"},
	} {
		if got := test.value.String(); got != test.want {
			t.Fatalf("Decision(%d).String() = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestPolicyKeepsSnapshotAfterFailedRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	whitelist, err := iplist.NewIPList(t.Context(), iplist.IPListConfig{Source: path, CacheDir: t.TempDir(), RefreshInterval: time.Nanosecond})
	if err != nil {
		t.Fatal(err)
	}
	p := New(t.Context(), Config{Whitelist: whitelist, RefreshInterval: time.Nanosecond})
	defer p.Stop()

	evaluator, err := p.Load(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if evaluator.Evaluate(netip.MustParseAddr("192.0.2.1")) != Whitelisted {
		t.Fatal("initial whitelist did not match")
	}
	if err := os.WriteFile(path, []byte("invalid entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	evaluator, err = p.Load(t.Context(), true)
	if err == nil {
		t.Fatal("invalid refresh unexpectedly succeeded")
	}
	if evaluator.Evaluate(netip.MustParseAddr("192.0.2.1")) != Whitelisted {
		t.Fatal("failed refresh replaced valid snapshot")
	}
}

func TestPolicyWhitelistPrecedesBlacklistExtra(t *testing.T) {
	dir := t.TempDir()
	white := filepath.Join(dir, "white.tsv")
	black := filepath.Join(dir, "black.tsv")
	if err := os.WriteFile(white, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(black, []byte("192.0.2.0/24\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	whitelist, err := iplist.NewIPList(context.Background(), iplist.IPListConfig{Source: white, CacheDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	blacklistExtra, err := iplist.NewIPList(context.Background(), iplist.IPListConfig{Source: black, CacheDir: dir})
	if err != nil {
		t.Fatal(err)
	}
	p := New(context.Background(), Config{Whitelist: whitelist, BlacklistExtra: blacklistExtra, RefreshInterval: time.Nanosecond})
	defer p.Stop()
	evaluator, err := p.Load(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	if evaluator.Evaluate(netip.MustParseAddr("192.0.2.1")) != Whitelisted {
		t.Fatal("whitelist did not take precedence")
	}
	if evaluator.Evaluate(netip.MustParseAddr("192.0.2.2")) != Blacklisted {
		t.Fatal("blacklist extra did not block")
	}
}
