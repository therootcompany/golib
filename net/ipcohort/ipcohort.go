package ipcohort

import (
	"cmp"
	"encoding/binary"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"os"
	"slices"
	"strings"
)

// ErrInputTooLarge is returned when a load operation reads more than
// maxBytes from its input. Callers wrap it with errors.Is to branch on
// the failure mode.
var ErrInputTooLarge = errors.New("ipcohort: input exceeds maxBytes")

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

func sortNets(nets []IPv4Net) {
	slices.SortFunc(nets, func(a, b IPv4Net) int {
		return cmp.Compare(a.networkBE, b.networkBE)
	})
}

// Size returns the total number of entries (hosts + nets).
func (c *Cohort) Size() int {
	return len(c.hosts) + len(c.nets)
}

// Contains reports whether ipStr falls within any host or subnet in the cohort.
// Returns an error if ipStr is unparseable; callers decide fail-open vs
// fail-closed for invalid input. IPv6 addresses parse but always return false
// (cohort is IPv4-only).
func (c *Cohort) Contains(ipStr string) (bool, error) {
	ip, err := netip.ParseAddr(ipStr)
	if err != nil {
		return false, fmt.Errorf("parse %q: %w", ipStr, err)
	}
	return c.ContainsAddr(ip), nil
}

// ContainsAddr reports whether ip falls within any host or subnet in the cohort.
// IPv6 addresses always return false (cohort is IPv4-only).
func (c *Cohort) ContainsAddr(ip netip.Addr) bool {
	if !ip.Is4() {
		return false
	}
	ip4 := ip.As4()
	ipU32 := binary.BigEndian.Uint32(ip4[:])

	if _, found := slices.BinarySearch(c.hosts, ipU32); found {
		return true
	}
	for _, net := range c.nets {
		if net.Contains(ipU32) {
			return true
		}
	}
	return false
}

// Parse builds a Cohort from a list of IP/CIDR strings. Returns an error
// listing every unparseable entry; the caller decides whether to proceed
// with a partial cohort by inspecting the returned (non-nil) Cohort.
func Parse(prefixList []string) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net
	var errs []error

	for i, raw := range prefixList {
		ipv4net, err := ParseIPv4(raw)
		if err != nil {
			errs = append(errs, fmt.Errorf("entry %d %q: %w", i, raw, err))
			continue
		}
		if ipv4net.prefix == 32 {
			hosts = append(hosts, ipv4net.networkBE)
		} else {
			nets = append(nets, ipv4net)
		}
	}

	slices.Sort(hosts)
	sortNets(nets)

	c := &Cohort{hosts: hosts, nets: nets}
	if len(errs) > 0 {
		return c, fmt.Errorf("ipcohort.Parse: %d invalid entries: %w",
			len(errs), errors.Join(errs...))
	}
	return c, nil
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
		return ipv4net, fmt.Errorf("not an IPv4 address: %s", raw)
	}
	ip4 := addr.As4()
	prefix := uint8(ippre.Bits()) // 0–32
	return NewIPv4Net(
		binary.BigEndian.Uint32(ip4[:]),
		prefix,
	), nil
}

// LoadFile reads path and parses it into a Cohort. Pass 0 for maxBytes to
// disable the cap, or a byte limit (e.g. 50<<20 for 50 MiB) to bound the
// read — protects against accidental fill-disk inputs and against an
// untrusted blocklist mirror serving an oversized file. There is no
// reasonable default size limit because cohort sources vary widely
// (hand-curated /etc-style allowlists ~1 KB through commercial threat
// feeds 100+ MB), so the caller MUST supply one.
//
// On open or read errors, returns nil + error. On parse errors only,
// returns the partial cohort + a joined error.
func LoadFile(path string, maxBytes int64) (*Cohort, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("could not load %q: %w", path, err)
	}
	defer func() { _ = f.Close() }()

	if maxBytes > 0 {
		if info, err := f.Stat(); err == nil && info.Size() > maxBytes {
			return nil, fmt.Errorf("%w: %s is %d bytes (limit %d)",
				ErrInputTooLarge, path, info.Size(), maxBytes)
		}
	}
	return ParseCSV(f, maxBytes)
}

// LoadFiles loads and merges multiple files into one Cohort. The
// maxBytes cap is applied per-file; a 50 MiB cap permits 4 × 50 MiB
// files, not 50 MiB total. Useful when hosts and networks are stored
// in separate files.
//
// On open or read errors, returns nil + error. On parse errors only,
// returns the partial cohort + a joined error so callers can choose
// to proceed with what loaded.
func LoadFiles(maxBytes int64, paths ...string) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net
	var parseErrs []error

	for _, path := range paths {
		c, err := LoadFile(path, maxBytes)
		if c == nil {
			return nil, err
		}
		if err != nil {
			parseErrs = append(parseErrs, fmt.Errorf("%s: %w", path, err))
		}
		hosts = append(hosts, c.hosts...)
		nets = append(nets, c.nets...)
	}

	slices.Sort(hosts)
	sortNets(nets)

	c := &Cohort{hosts: hosts, nets: nets}
	if len(parseErrs) > 0 {
		return c, errors.Join(parseErrs...)
	}
	return c, nil
}

// ParseCSV parses CSV cohort data from r. Pass 0 for maxBytes to disable
// the cap. When maxBytes > 0, exceeding the limit returns ErrInputTooLarge
// (with whatever cohort entries were parsed before the cutoff, so the
// caller can choose partial-use).
func ParseCSV(r io.Reader, maxBytes int64) (*Cohort, error) {
	cr := &countingReader{r: r}
	src := io.Reader(cr)
	if maxBytes > 0 {
		// +1 so n>maxBytes signals "exceeded" without an extra read.
		src = io.LimitReader(cr, maxBytes+1)
	}
	csvReader := csv.NewReader(src)
	csvReader.FieldsPerRecord = -1

	c, err := ReadAll(csvReader)
	if maxBytes > 0 && cr.n > maxBytes {
		return c, fmt.Errorf("%w (read %d, limit %d)", ErrInputTooLarge, cr.n, maxBytes)
	}
	return c, err
}

// countingReader tracks total bytes read so ParseCSV can detect a
// LimitReader-induced cutoff.
type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// ReadAll reads CSV records from r and builds a Cohort. Returns an error
// listing every unparseable entry (with line number); the returned Cohort
// is non-nil and contains every entry that did parse, so callers can choose
// to proceed with a partial cohort.
func ReadAll(r *csv.Reader) (*Cohort, error) {
	var hosts []uint32
	var nets []IPv4Net
	var errs []error

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

		ipv4net, err := ParseIPv4(raw)
		if err != nil {
			line, _ := r.FieldPos(0)
			errs = append(errs, fmt.Errorf("line %d %q: %w", line, raw, err))
			continue
		}

		if ipv4net.prefix == 32 {
			hosts = append(hosts, ipv4net.networkBE)
		} else {
			nets = append(nets, ipv4net)
		}
	}

	slices.Sort(hosts)
	sortNets(nets)

	c := &Cohort{hosts: hosts, nets: nets}
	if len(errs) > 0 {
		return c, fmt.Errorf("ipcohort.ReadAll: %d invalid entries: %w",
			len(errs), errors.Join(errs...))
	}
	return c, nil
}
