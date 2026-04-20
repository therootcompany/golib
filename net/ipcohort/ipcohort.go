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
	"strings"
)

// IPv4Net represents a subnet or single address (/32).
// 6 bytes: networkBE uint32 + prefix uint8 + shift uint8.
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
	mask := uint32(0xFFFFFFFF << r.shift)
	return (ip & mask) == r.networkBE
}

// Cohort is an immutable, read-only set of IPv4 addresses and subnets.
// Contains is safe for concurrent use without locks.
//
// hosts holds sorted /32 addresses for O(log n) binary search.
// nets holds CIDR ranges (prefix < 32) for O(k) linear scan — typically small.
type Cohort struct {
	hosts []uint32
	nets  []IPv4Net
}

func New() *Cohort {
	return &Cohort{}
}

// Size returns the total number of entries (hosts + nets).
func (c *Cohort) Size() int {
	return len(c.hosts) + len(c.nets)
}

// Contains reports whether ipStr falls within any host or subnet in the cohort.
// Returns true on parse error (fail-closed).
func (c *Cohort) Contains(ipStr string) bool {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return true
	}
	ip4 := ip.As4()
	ipU32 := binary.BigEndian.Uint32(ip4[:])

	_, found := slices.BinarySearch(c.hosts, ipU32)
	if found {
		return true
	}

	for _, net := range c.nets {
		if net.Contains(ipU32) {
			return true
		}
	}
	return false
}

func Parse(prefixList []string) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net

	for _, raw := range prefixList {
		ipv4net, err := ParseIPv4(raw)
		if err != nil {
			log.Printf("skipping invalid entry: %q", raw)
			continue
		}
		if ipv4net.prefix == 32 {
			hosts = append(hosts, ipv4net.networkBE)
		} else {
			nets = append(nets, ipv4net)
		}
	}

	slices.Sort(hosts)
	slices.SortFunc(nets, func(a, b IPv4Net) int {
		if a.networkBE < b.networkBE {
			return -1
		}
		if a.networkBE > b.networkBE {
			return 1
		}
		return 0
	})

	return &Cohort{hosts: hosts, nets: nets}, nil
}

func ParseIPv4(raw string) (ipv4net IPv4Net, err error) {
	var ippre netip.Prefix
	var ip netip.Addr
	if strings.Contains(raw, "/") {
		ippre, err = netip.ParsePrefix(raw)
		if err != nil {
			return ipv4net, err
		}
	} else {
		ip, err = netip.ParseAddr(raw)
		if err != nil {
			return ipv4net, err
		}
		ippre = netip.PrefixFrom(ip, 32)
	}

	addr := ippre.Addr()
	if !addr.Is4() {
		return ipv4net, fmt.Errorf("IPv6 not supported: %s", raw)
	}
	ip4 := addr.As4()
	prefix := uint8(ippre.Bits()) // 0–32
	return NewIPv4Net(
		binary.BigEndian.Uint32(ip4[:]),
		prefix,
	), nil
}

func LoadFile(path string) (*Cohort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not load %q: %v", path, err)
	}
	defer f.Close()

	return ParseCSV(f)
}

// LoadFiles loads and merges multiple files into one Cohort.
// Useful when hosts and networks are stored in separate files.
func LoadFiles(paths ...string) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net

	for _, path := range paths {
		c, err := LoadFile(path)
		if err != nil {
			return nil, err
		}
		hosts = append(hosts, c.hosts...)
		nets = append(nets, c.nets...)
	}

	slices.Sort(hosts)
	slices.SortFunc(nets, func(a, b IPv4Net) int {
		if a.networkBE < b.networkBE {
			return -1
		}
		if a.networkBE > b.networkBE {
			return 1
		}
		return 0
	})

	return &Cohort{hosts: hosts, nets: nets}, nil
}

func ParseCSV(f io.Reader) (*Cohort, error) {
	r := csv.NewReader(f)
	r.FieldsPerRecord = -1

	return ReadAll(r)
}

func ReadAll(r *csv.Reader) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net

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

		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}

		// skip IPv6
		if strings.Contains(raw, ":") {
			continue
		}

		ipv4net, err := ParseIPv4(raw)
		if err != nil {
			log.Printf("skipping invalid entry: %q", raw)
			continue
		}

		if ipv4net.prefix == 32 {
			hosts = append(hosts, ipv4net.networkBE)
		} else {
			nets = append(nets, ipv4net)
		}
	}

	slices.Sort(hosts)
	slices.SortFunc(nets, func(a, b IPv4Net) int {
		if a.networkBE < b.networkBE {
			return -1
		}
		if a.networkBE > b.networkBE {
			return 1
		}
		return 0
	})

	return &Cohort{hosts: hosts, nets: nets}, nil
}
