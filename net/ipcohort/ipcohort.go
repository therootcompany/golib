package ipcohort

import (
	"encoding/binary"
	"encoding/csv"
	"fmt"
	"io"
	"log"
	"net/netip"
	"os"
	"slices"
	"sort"
	"strings"
	"sync/atomic"
)

// Either a subnet or single address (subnet with /32 CIDR prefix)
type IPv4Net struct {
	networkBE uint32
	prefix    uint8
	shift     uint8
}

func NewIPv4Net(ip4be uint32, prefix uint8) IPv4Net {
	return IPv4Net{
		networkBE: ip4be,
		prefix:    prefix,
		shift:     32 - prefix,
	}
}

func (r IPv4Net) Contains(ip uint32) bool {
	mask := uint32(0xFFFFFFFF << (r.shift))
	return (ip & mask) == r.networkBE
}

func LoadFile(path string, unsorted bool) (*Cohort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not load %q: %v", path, err)
	}
	defer f.Close()

	return ParseCSV(f, unsorted)
}

func ParseCSV(f io.Reader, unsorted bool) (*Cohort, error) {
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	return ReadAll(r, unsorted)
}

func ReadAll(r *csv.Reader, unsorted bool) (*Cohort, error) {
	var ranges []IPv4Net
	for {
		record, err := r.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("csv read error: %w", err)
		}

		if len(record) == 0 {
			continue
		}

		raw := strings.TrimSpace(record[0])

		// Skip comments/empty
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		// skip IPv6
		if strings.Contains(raw, ":") {
			continue
		}

		var ippre netip.Prefix
		var ip netip.Addr
		if strings.Contains(raw, "/") {
			ippre, err = netip.ParsePrefix(raw)
			if err != nil {
				log.Printf("skipping invalid entry: %q", raw)
				continue
			}
		} else {
			ip, err = netip.ParseAddr(raw)
			if err != nil {
				log.Printf("skipping invalid entry: %q", raw)
				continue
			}
			ippre = netip.PrefixFrom(ip, 32)
		}

		ip4 := ippre.Addr().As4()
		prefix := uint8(ippre.Bits()) // 0-32
		ranges = append(ranges, NewIPv4Net(
			binary.BigEndian.Uint32(ip4[:]),
			prefix,
		))
	}

	if unsorted {
		// Sort by network address (required for binary search)
		sort.Slice(ranges, func(i, j int) bool {
			// Note: we could also sort by prefix (largest first)
			return ranges[i].networkBE < ranges[j].networkBE
		})

		// Note: we could also merge ranges here
	}

	sizedList := make([]IPv4Net, len(ranges))
	copy(sizedList, ranges)

	ipList := &Cohort{}
	ipList.Store(&innerCohort{ranges: sizedList})
	return ipList, nil
}

type Cohort struct {
	atomic.Pointer[innerCohort]
}

// for ergonomic - so we can access the slice without dereferencing
type innerCohort struct {
	ranges []IPv4Net
}

func (c *Cohort) Swap(next *Cohort) {
	c.Store(next.Load())
}

func (c *Cohort) Size() int {
	return len(c.Load().ranges)
}

func (c *Cohort) Contains(ipStr string) bool {
	cohort := c.Load()

	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return true
	}
	ip4 := ip.As4()
	ipU32 := binary.BigEndian.Uint32(ip4[:])

	idx, found := slices.BinarySearchFunc(cohort.ranges, ipU32, func(r IPv4Net, target uint32) int {
		if r.networkBE < target {
			return -1
		}
		if r.networkBE > target {
			return 1
		}
		return 0
	})
	if found {
		return true
	}

	// Check the range immediately before the insertion point
	if idx > 0 {
		if cohort.ranges[idx-1].Contains(ipU32) {
			return true
		}
	}

	return false
}
