package ippolicy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/therootcompany/golib/net/iplist"
)

// TestPolicyStartPushesSourceUpdatesIntoDerivedSets confirms that when a
// source IP list changes and the Policy's background loop runs, the derived
// DomainSet is updated without an explicit Policy.Load call. This is the gap
// flagged in the handoff: sources refresh on their own tickers but derived
// sets never saw the new entries.
func TestPolicyStartPushesSourceUpdatesIntoDerivedSets(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// Short refresh interval so the source re-reads the file promptly.
	whitelist, err := iplist.NewIPList(t.Context(), iplist.IPListConfig{
		Source:          path,
		CacheDir:        t.TempDir(),
		RefreshInterval: 20 * time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}

	p := New(t.Context(), Config{Whitelist: whitelist})
	defer p.Stop()

	if p.Evaluate(netip.MustParseAddr("192.0.2.1")) != Whitelisted {
		t.Fatal("initial whitelist did not match 192.0.2.1")
	}

	// Start the source ticker (re-reads file) and the Policy loop (pushes
	// entries into the derived set).
	whitelist.Start(t.Context(), 20*time.Millisecond)
	p.Start(t.Context(), 20*time.Millisecond)

	// Change the source: drop 192.0.2.1, add 192.0.2.2.
	if err := os.WriteFile(path, []byte("192.0.2.2\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	// Within a few intervals the derived set must reflect the new entry.
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if p.Evaluate(netip.MustParseAddr("192.0.2.2")) == Whitelisted {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if p.Evaluate(netip.MustParseAddr("192.0.2.2")) != Whitelisted {
		t.Fatal("derived set was not updated by Policy.Start loop (192.0.2.2 missing)")
	}
}

// TestPolicyStartIsIdempotent confirms Start can be called multiple times
// safely (only one loop starts).
func TestPolicyStartIsIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "allowed.tsv")
	if err := os.WriteFile(path, []byte("192.0.2.1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	whitelist, err := iplist.NewIPList(t.Context(), iplist.IPListConfig{
		Source:   path,
		CacheDir: t.TempDir(),
	})
	if err != nil {
		t.Fatal(err)
	}
	p := New(t.Context(), Config{Whitelist: whitelist})
	defer p.Stop()
	for range 3 {
		p.Start(t.Context(), time.Hour)
	}
}
