package csvdb

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"os"
)

// createTemp creates a temporary file within root using the pattern
// <name>.<rnd>.tmp, where <rnd> is a 32-bit random value encoded as
// URL-safe base64 (6 characters). The file is created with O_CREATE|O_EXCL
// and 0600 permissions.
//
// 2^32 possible names is sufficient to avoid collisions without retry.
func createTemp(root *os.Root, name string) (*os.File, string, error) {
	var buf [4]byte
	if _, err := rand.Read(buf[:]); err != nil {
		return nil, "", fmt.Errorf("generate temp suffix: %w", err)
	}
	tmpName := name + "." + base64.RawURLEncoding.EncodeToString(buf[:]) + ".tmp"
	f, err := root.OpenFile(tmpName, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return nil, "", err
	}
	return f, tmpName, nil
}

// AtomicWrite writes data to a temp file in root, then atomically renames it
// to name. If the write or rename fails, the temp file is removed.
func AtomicWrite(root *os.Root, name string, write func(*os.File) error) error {
	tmp, tmpName, err := createTemp(root, name)
	if err != nil {
		return fmt.Errorf("create temp: %w", err)
	}
	defer func() { _ = root.Remove(tmpName) }()
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close temp: %w", err)
	}
	return root.Rename(tmpName, name)
}
