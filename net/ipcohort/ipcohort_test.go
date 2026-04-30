package ipcohort_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/therootcompany/golib/net/ipcohort"
)

func TestParseIPv4(t *testing.T) {
	tests := []struct {
		raw     string
		wantErr bool
	}{
		{"1.2.3.4", false},
		{"1.2.3.4/32", false},
		{"10.0.0.0/8", false},
		{"192.168.0.0/16", false},
		{"0.0.0.0/0", false},
		{"", true},
		{"not-an-ip", true},
		{"1.2.3.4/33", true},
	}
	for _, tt := range tests {
		_, err := ipcohort.ParseIPv4(tt.raw)
		if (err != nil) != tt.wantErr {
			t.Errorf("ParseIPv4(%q): got err=%v, wantErr=%v", tt.raw, err, tt.wantErr)
		}
	}
}

func TestContains_SingleHosts(t *testing.T) {
	c, err := ipcohort.Parse([]string{"1.2.3.4", "5.6.7.8", "10.0.0.1"})
	if err != nil {
		t.Fatal(err)
	}

	hits := []string{"1.2.3.4", "5.6.7.8", "10.0.0.1"}
	misses := []string{"1.2.3.5", "5.6.7.7", "10.0.0.2", "0.0.0.0"}

	for _, ip := range hits {
		if !c.Contains(ip) {
			t.Errorf("expected %s to be in cohort", ip)
		}
	}
	for _, ip := range misses {
		if c.Contains(ip) {
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
		if !c.Contains(ip) {
			t.Errorf("expected %s to be in cohort (CIDR)", ip)
		}
	}
	for _, ip := range misses {
		if c.Contains(ip) {
			t.Errorf("expected %s NOT to be in cohort (CIDR)", ip)
		}
	}
}

func TestContains_Mixed(t *testing.T) {
	c, err := ipcohort.Parse([]string{"1.2.3.4", "10.0.0.0/8"})
	if err != nil {
		t.Fatal(err)
	}

	if !c.Contains("1.2.3.4") {
		t.Error("host miss")
	}
	if !c.Contains("10.5.5.5") {
		t.Error("CIDR miss")
	}
	if c.Contains("1.2.3.5") {
		t.Error("false positive for host-adjacent")
	}
}

func TestContains_FailClosed(t *testing.T) {
	c, _ := ipcohort.Parse([]string{"1.2.3.4"})
	// Unparseable input should return true (fail-closed).
	if !c.Contains("not-an-ip") {
		t.Error("expected fail-closed true for unparseable IP")
	}
}


func TestContains_Empty(t *testing.T) {
	c, err := ipcohort.Parse(nil)
	if err != nil {
		t.Fatal(err)
	}
	if c.Contains("1.2.3.4") {
		t.Error("empty cohort should not contain anything")
	}
}

func TestSize(t *testing.T) {
	c, _ := ipcohort.Parse([]string{"1.2.3.4", "5.6.7.8", "10.0.0.0/8"})
	if got, want := c.Size(), 3; got != want {
		t.Errorf("Size() = %d, want %d", got, want)
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
	if !c.Contains("1.2.3.4") {
		t.Error("missing 1.2.3.4")
	}
	if !c.Contains("10.5.5.5") {
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
	if !c.Contains("192.168.0.100") {
		t.Error("missing merged CIDR member")
	}
}

