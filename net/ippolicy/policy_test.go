package ippolicy

import (
	"context"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

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
	for _, test := range []struct {
		value RefreshKind
		want  string
	}{
		{RefreshSuccess, "success"},
		{RefreshFailure, "failure"},
		{RefreshFallback, "fallback"},
		{RefreshKind(99), "refresh(99)"},
	} {
		if got := test.value.String(); got != test.want {
			t.Fatalf("RefreshKind(%d).String() = %q, want %q", test.value, got, test.want)
		}
	}
}

func TestPolicyKeepsSnapshotAfterFailedRefresh(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	whitelist, err := iplist.NewSource(t.Context(), iplist.SourceConfig{Source: path})
	if err != nil {
		t.Fatal(err)
	}
	p := New(t.Context(), Config{Whitelist: whitelist})
	defer func() { _ = p.Close() }()

	if p.Evaluate(netip.MustParseAddr("192.0.2.1")) != Whitelisted {
		t.Fatal("initial whitelist did not match")
	}
	if err := os.WriteFile(path, []byte("invalid entry\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := whitelist.Refresh(); err == nil {
		t.Fatal("invalid refresh unexpectedly succeeded")
	}
	if p.Evaluate(netip.MustParseAddr("192.0.2.1")) != Whitelisted {
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
	whitelist, err := iplist.NewSource(context.Background(), iplist.SourceConfig{Source: white})
	if err != nil {
		t.Fatal(err)
	}
	extra, err := iplist.NewSource(context.Background(), iplist.SourceConfig{Source: black})
	if err != nil {
		t.Fatal(err)
	}
	p := New(context.Background(), Config{Whitelist: whitelist, BlacklistExtra: extra})
	defer func() { _ = p.Close() }()
	if p.Evaluate(netip.MustParseAddr("192.0.2.1")) != Whitelisted {
		t.Fatal("whitelist did not take precedence")
	}
	if p.Evaluate(netip.MustParseAddr("192.0.2.2")) != Blacklisted {
		t.Fatal("extra blacklist did not block")
	}
}
