package geoip

import (
	"bufio"
	"fmt"
	"os"
	"strings"
)

// Conf holds the fields parsed from a geoipupdate-style config file.
type Conf struct {
	AccountID         string
	LicenseKey        string
	EditionIDs        []string
	DatabaseDirectory string
}

// ParseConf reads a geoipupdate-style config file (whitespace-separated
// key/value pairs, # comments). Compatible with GeoIP.conf files used by
// the official geoipupdate tool.
func ParseConf(path string) (*Conf, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	kv := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, _ := strings.Cut(line, " ")
		kv[strings.TrimSpace(key)] = strings.TrimSpace(value)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	c := &Conf{
		AccountID:         kv["AccountID"],
		LicenseKey:        kv["LicenseKey"],
		DatabaseDirectory: kv["DatabaseDirectory"],
	}
	if c.AccountID == "" || c.LicenseKey == "" {
		return nil, fmt.Errorf("AccountID and LicenseKey are required in %s", path)
	}
	if ids := kv["EditionIDs"]; ids != "" {
		c.EditionIDs = strings.Fields(ids)
	}
	return c, nil
}
