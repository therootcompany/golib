package ipcohort_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/therootcompany/golib/net/ipcohort"
)

func mustContain(t *testing.T, c *ipcohort.Cohort, ip string) bool {
	t.Helper()
	found, err := c.Contains(ip)
	if err != nil {
		t.Fatalf("Contains(%q): unexpected err: %v", ip, err)
	}
	return found
}

func TestContains_SingleHosts(t *testing.T) {
	c, err := ipcohort.Parse([]string{"1.2.3.4", "5.6.7.8", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	hits := []string{"1.2.3.4", "5.6.7.8", "10.0.0.1"}
	misses := []string{"1.2.3.5", "5.6.7.7", "10.0.0.2", "0.0.0.0"}

	for _, ip := range hits {
		if !mustContain(t, c, ip) {
			t.Errorf("expected %s to be in cohort", ip)
		}
	}
	for _, ip := range misses {
		if mustContain(t, c, ip) {
			t.Errorf("expected %s NOT to be in cohort", ip)
		}
	}
}

func TestContains_CIDRRanges(t *testing.T) {
	c, err := ipcohort.Parse([]string{"10.0.0.0/8", "192.168.1.0/24"})
	if err != nil {
		t.Fatal(err)
	}

	hits := []string{
		"10.0.0.0", "10.0.0.1", "10.255.255.255",
		"192.168.1.0", "192.168.1.1", "192.168.1.254", "192.168.1.255",
	}
	misses := []string{
		"9.255.255.255", "11.0.0.0",
		"192.168.0.255", "192.168.2.0",
	}

	for _, ip := range hits {
		if !mustContain(t, c, ip) {
			t.Errorf("expected %s to be in cohort (CIDR)", ip)
		}
	}
	for _, ip := range misses {
		if mustContain(t, c, ip) {
			t.Errorf("expected %s NOT to be in cohort (CIDR)", ip)
		}
	}
}

// AntiChain: nets sorted by networkBE, none contained in another. Verifies
// the bsearch+single-check path picks the right net for IPs whose binary
// search lands on a non-matching neighbor.
func TestContains_AntiChain(t *testing.T) {
	c, err := ipcohort.Parse([]string{
		"9.0.0.0/24",     // narrow, just before the /8
		"10.0.0.0/8",     // broad
		"20.0.0.0/24",    // narrow, after the /8
		"30.0.0.0/16",    // mid
	})
	if err != nil {
		t.Fatal(err)
	}
	hits := []string{
		"9.0.0.50",
		"10.5.5.5",   // bsearch lands on 10.0.0.0/8 — match
		"10.255.255.255",
		"20.0.0.5",
		"30.0.99.1",
	}
	misses := []string{
		"8.255.255.255", // before everything
		"9.0.1.0",       // past 9.0.0.0/24, before /8
		"11.0.0.0",      // past /8, before 20.0.0.0/24
		"20.0.1.0",      // past /24
		"31.0.0.0",      // past /16
	}
	for _, ip := range hits {
		if !mustContain(t, c, ip) {
			t.Errorf("expected %s to be in cohort", ip)
		}
	}
	for _, ip := range misses {
		if mustContain(t, c, ip) {
			t.Errorf("expected %s NOT to be in cohort", ip)
		}
	}
}

func TestContains_Empty(t *testing.T) {
	c, err := ipcohort.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if mustContain(t, c, "1.2.3.4") {
		t.Error("empty cohort should not contain anything")
	}
}

func TestLoadFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "list.txt")
	content := "# comment\n1.2.3.4\n10.0.0.0/8\n\n5.6.7.8\n"
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}

	c, err := ipcohort.LoadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Size() != 3 {
		t.Errorf("Size() = %d, want 3", c.Size())
	}
	if !mustContain(t, c, "1.2.3.4") {
		t.Error("missing 1.2.3.4")
	}
	if !mustContain(t, c, "10.5.5.5") {
		t.Error("missing CIDR member 10.5.5.5")
	}
}

func TestLoadFiles_Merge(t *testing.T) {
	dir := t.TempDir()

	f1 := filepath.Join(dir, "singles.txt")
	f2 := filepath.Join(dir, "networks.txt")
	os.WriteFile(f1, []byte("1.2.3.4\n5.6.7.8\n"), 0o644)
	os.WriteFile(f2, []byte("192.168.0.0/24\n"), 0o644)

	c, err := ipcohort.LoadFiles(f1, f2)
	if err != nil {
		t.Fatal(err)
	}
	if c.Size() != 3 {
		t.Errorf("Size() = %d, want 3", c.Size())
	}
	if !mustContain(t, c, "192.168.0.100") {
		t.Error("missing merged CIDR member")
	}
}

