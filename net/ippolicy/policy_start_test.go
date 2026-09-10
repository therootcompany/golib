package ippolicy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/therootcompany/golib/net/iplist"
)

func TestPolicyLoadPublishesUpdatedSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	whitelist, err := iplist.NewIPList(t.Context(), iplist.IPListConfig{
		Source: path, CacheDir: t.TempDir(), RefreshInterval: time.Nanosecond,
	})
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
	if err := os.WriteFile(path, []byte("192.0.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	evaluator, err = p.Load(t.Context(), true)
	if err != nil {
		t.Fatal(err)
	}
	if evaluator.Evaluate(netip.MustParseAddr("192.0.2.2")) != Whitelisted {
		t.Fatal("updated whitelist did not match")
	}
}
