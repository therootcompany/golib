package geoip

import (
	"bufio"
	"errors"
	"strings"
)

// Conf holds the fields parsed from a geoipupdate-style config file.
//
// GeoLite2 is free: sign up at https://www.maxmind.com/en/geolite2/signup
// to get an AccountID and generate a LicenseKey, then write them to
// GeoIP.conf alongside the desired EditionIDs:
//
//	AccountID   123456
//	LicenseKey  xxxxxxxxxxxxxxxx
//	EditionIDs  GeoLite2-City GeoLite2-ASN
type Conf struct {
	AccountID         string
	LicenseKey        string
	EditionIDs        []string
	DatabaseDirectory string
}

// ErrMissingCredentials is returned by ParseConf when AccountID or LicenseKey
// is absent from the input.
var ErrMissingCredentials = errors.New("AccountID and LicenseKey are required")

// ParseConf parses a geoipupdate-style config (whitespace-separated key/value
// pairs, # comments). Compatible with GeoIP.conf files used by the official
// geoipupdate tool.
func ParseConf(s string) (*Conf, error) {
	kv := make(map[string]string)
	scanner := bufio.NewScanner(strings.NewReader(s))
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
		return nil, ErrMissingCredentials
	}
	if ids := kv["EditionIDs"]; ids != "" {
		c.EditionIDs = strings.Fields(ids)
	}
	return c, nil
}
