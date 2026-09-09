package ippolicy

import (
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/therootcompany/golib/net/ipcohort"
)

func TestPrefixSetContainsZeroValue(t *testing.T) {
	var ps PrefixSet
	// Zero-value must not panic — Contains self-initialises via CAS.
	if ps.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("zero-value PrefixSet must not contain an address")
	}
	// After first call the cohort should be non-nil.
	if ps.cohort.Load() == nil {
		t.Fatal("cohort should be non-nil after Contains")
	}
}

func TestCachedCohortValidRequiresFiles(t *testing.T) {
	dir := t.TempDir()
	present := filepath.Join(dir, "present")
	if err := writeFile(present); err != nil {
		t.Fatal(err)
	}
	cohort, err := ipcohort.Parse([]string{"192.0.2.0/24"})
	if err != nil {
		t.Fatal(err)
	}

	if !cachedCohortValid(false, cohort, []string{present}) {
		t.Fatal("fresh metadata and present files should use the cache")
	}
	if cachedCohortValid(false, cohort, []string{present, filepath.Join(dir, "gone")}) {
		t.Fatal("missing data file must invalidate the cache")
	}
	if cachedCohortValid(false, nil, []string{present}) {
		t.Fatal("nil cohort must not be used")
	}
	if cachedCohortValid(true, cohort, []string{present}) {
		t.Fatal("updated repo must reload")
	}
}

func writeFile(path string) error {
	return os.WriteFile(path, nil, 0o600)
}
