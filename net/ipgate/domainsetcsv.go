package ipgate

import (
	"fmt"
	"io"
	"net/netip"
	"strings"
)

// RecordReader is satisfied by *csv.Reader.
type RecordReader interface {
	Read() (record []string, err error)
}

// ParseDomainSet reads rows from r and returns static CIDR prefixes and
// hostnames to resolve. The first row is skipped when it contains no IP,
// prefix, or dotted hostname (header detection).
func ParseDomainSet(r RecordReader) (staticPrefixes []string, domains []string, err error) {
	firstRow := true
	for {
		record, readErr := r.Read()
		if readErr == io.EOF {
			break
		}
		if readErr != nil {
			return nil, nil, fmt.Errorf("csv read: %w", readErr)
		}
		if len(record) == 0 {
			continue
		}

		raw := strings.TrimSpace(record[0])

		if firstRow {
			firstRow = false
			if _, err := netip.ParseAddr(raw); err != nil {
				if _, err := netip.ParsePrefix(raw); err != nil {
					if !strings.Contains(raw, ".") {
						continue
					}
				}
			}
		}
		if raw == "" {
			continue
		}

		if _, err := netip.ParseAddr(raw); err == nil {
			staticPrefixes = append(staticPrefixes, raw+"/32")
			continue
		}
		if _, err := netip.ParsePrefix(raw); err == nil {
			staticPrefixes = append(staticPrefixes, raw)
			continue
		}

		domains = append(domains, raw)
	}

	return staticPrefixes, domains, nil
}
