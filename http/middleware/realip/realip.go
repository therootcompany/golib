// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) has dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// SPDX-License-Identifier: CC0-1.0

package realip

import (
	"context"
	"fmt"
	"math/bits"
	"net"
	"net/http"
	"strings"
)

// realip resolves the client address of a request that arrived through a
// proxy (a TLS router, Caddy, nginx, a load balancer).
//
// Two entry points, same behaviour, different input:
//
//	Trust([]net.IP)                 - exact addresses; for a list that is
//	                                 already parsed (a config struct, an IP
//	                                 policy snapshot)
//	MustTrust("10.11.2.55", "10.11.0.0/16")
//	                                - bare IPs and CIDRs from config; panics
//                                 on a value it cannot parse, so a typo fails
//                                 at startup instead of silently trusting
//                                 nothing at request time
//
// An empty (or nil) trusted set trusts no proxy: the headers are ignored and
// the peer address is used. That is the safe default. To positively trust any
// proxy, say so explicitly:
//
//	realip.MustTrust("0.0.0.0/0", "::/0")
//
// Headers are read in this order:
//
//	1. X-Forwarded-For   (de facto standard, a chain)
//	2. Forwarded         (RFC 7239, the standards-track chain)
//	3. X-Real-IP         (nginx, a single address)
//
// Vendor headers such as CF-Connecting-IP are deliberately not read: a CDN
// that sends them also sends X-Forwarded-For, and the peer-address gate below
// already decides what is trustworthy.
//
// The chain is walked from the hop nearest this server; the first address not
// in the allow list is the client. A hop that cannot be parsed stops the walk:
// nothing beyond garbage is trustworthy, so no client address is inferred and
// the peer address is used (fail closed).
//
// r.RemoteAddr is rewritten in place with the client address, so every
// handler, logger, and limiter sees the client without any new API. The
// address the request actually arrived from - the proxy - is available with
// PeerIP(r) even after the rewrite.
//
// Ordering matters: Trust must run before the logger and before any rate
// limiter, otherwise the limiter counts the router instead of the client.

// trustedProxies is the resolved allow list of proxy addresses. allProxies is
// set by a /0 prefix so a single wildcard covers both address families.
type trustedProxies struct {
	exact      map[string]struct{}
	prefixes   []*net.IPNet
	allProxies bool
}

func (t trustedProxies) contains(ip net.IP) bool {
	if t.allProxies {
		return true
	}
	if ip == nil {
		return false
	}
	if len(t.exact) > 0 {
		if _, ok := t.exact[ip.String()]; ok {
			return true
		}
	}
	for _, prefix := range t.prefixes {
		if prefix.Contains(ip) {
			return true
		}
	}
	return false
}

// Trust replaces r.RemoteAddr with the client address inferred from the
// forwarding headers, but only when the address the request actually arrived
// from is in trusted. nil or empty trusts nothing.
func Trust(trusted []net.IP) func(http.Handler) http.Handler {
	set := trustedProxies{exact: make(map[string]struct{}, len(trusted))}
	for _, ip := range trusted {
		if ip == nil {
			continue
		}
		set.exact[ip.String()] = struct{}{}
	}
	return withRealIP(set)
}

// MustTrust is Trust for addresses and CIDRs given as strings. It panics on
// anything it cannot parse: a proxy allow list is not something to discover
// while serving a request.
func MustTrust(trusted ...string) func(http.Handler) http.Handler {
	set := trustedProxies{exact: make(map[string]struct{}, len(trusted))}
	for _, value := range trusted {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}

		if strings.IndexByte(value, '/') >= 0 {
			_, prefix, err := net.ParseCIDR(value)
			if err != nil {
				panic(fmt.Errorf("MustTrust: %q is not a valid IP or CIDR: %w", value, err))
			}
			if isEverything(prefix) {
				set.allProxies = true
				continue
			}
			set.prefixes = append(set.prefixes, prefix)
			continue
		}

		ip := net.ParseIP(value)
		if ip == nil {
			panic(fmt.Errorf("MustTrust: %q is not a valid IP or CIDR", value))
		}
		set.exact[ip.String()] = struct{}{}
	}
	return withRealIP(set)
}

// isEverything reports whether a prefix covers every address (0.0.0.0/0 or ::/0).
func isEverything(prefix *net.IPNet) bool {
	for _, maskByte := range prefix.Mask {
		if bits.OnesCount8(maskByte) != 0 {
			return false
		}
	}
	return true
}

// peerContextKey holds the address the connection actually arrived from, so it
// survives the r.RemoteAddr rewrite.
type peerContextKey struct{}

func withRealIP(trusted trustedProxies) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			peer, err := peerAddress(r)
			if err == nil {
				r = r.WithContext(context.WithValue(r.Context(), peerContextKey{}, peer))
			}

			if err != nil || !trusted.contains(peer) {
				// The request did not arrive from a proxy we trust, so the
				// forwarding headers are not evidence of anything.
				next.ServeHTTP(w, r)
				return
			}

			client := forwardedClientIP(r, trusted)
			if client == nil {
				client = peer
			}

			r.RemoteAddr = client.String()
			next.ServeHTTP(w, r)
		})
	}
}

// PeerIP returns the address the request actually arrived from - the proxy
// directly connected to this server - even after Trust has rewritten
// r.RemoteAddr. It returns nil when the peer address cannot be parsed. When
// Trust is not in the chain, PeerIP simply reports the peer of RemoteAddr.
func PeerIP(r *http.Request) net.IP {
	if peer, ok := r.Context().Value(peerContextKey{}).(net.IP); ok {
		return peer
	}
	return peerAddressOrRemoteAddr(r)
}

// peerAddressOrRemoteAddr parses RemoteAddr tolerantly: a bare address with no
// port is accepted.
func peerAddressOrRemoteAddr(r *http.Request) net.IP {
	host := r.RemoteAddr
	if h, _, err := net.SplitHostPort(r.RemoteAddr); err == nil {
		host = h
	}
	return net.ParseIP(host)
}

// peerAddress extracts the address the connection actually arrived from.
func peerAddress(r *http.Request) (net.IP, error) {
	ip := peerAddressOrRemoteAddr(r)
	if ip == nil {
		return nil, fmt.Errorf("peer address %q is not an IP", r.RemoteAddr)
	}
	return ip, nil
}

// forwardedClientIP returns the client address from the forwarding headers.
func forwardedClientIP(r *http.Request, trusted trustedProxies) net.IP {
	// RFC 7230: repeated header fields are equivalent to one comma-separated
	// value, so merge them before parsing.
	if chain := r.Header.Values("X-Forwarded-For"); len(chain) > 0 {
		return walkChain(xffEntries(chain), trusted)
	}
	if chain := r.Header.Values("Forwarded"); len(chain) > 0 {
		return walkChain(forwardedEntries(chain), trusted)
	}

	// No chain: X-Real-IP (nginx). The last value wins - it is the one written
	// by the hop closest to this server, and the peer gate already established
	// this server is only reachable through trusted proxies.
	values := r.Header.Values("X-Real-IP")
	if len(values) > 0 {
		return parseAddress(values[len(values)-1])
	}
	return nil
}

// walkChain walks hop values from the hop nearest this server (right to left)
// and returns the first address not in the allow list. An unparseable hop
// stops the walk and returns nil: nothing further out is trustworthy after
// garbage. When every hop is trusted, the leftmost hop is returned.
func walkChain(hops []string, trusted trustedProxies) net.IP {
	for i := len(hops) - 1; i >= 0; i-- {
		ip := parseAddress(hops[i])
		if ip == nil {
			return nil
		}
		if !trusted.contains(ip) {
			return ip
		}
	}
	if len(hops) > 0 {
		return parseAddress(hops[0])
	}
	return nil
}

// xffEntries splits repeated X-Forwarded-For fields into hop values in header
// order (client first, each proxy appends).
func xffEntries(headers []string) []string {
	var hops []string
	for _, header := range headers {
		for _, hop := range strings.Split(header, ",") {
			hop = strings.TrimSpace(hop)
			if hop != "" {
				hops = append(hops, hop)
			}
		}
	}
	return hops
}

// forwardedEntries turns RFC 7239 Forwarded fields into their "for" values in
// header order. host, proto, and by parameters are ignored; an entry without
// a "for" parameter contributes nothing.
func forwardedEntries(headers []string) []string {
	var hops []string
	for _, header := range headers {
		for _, entry := range strings.Split(header, ",") {
			for _, param := range strings.Split(entry, ";") {
				name, value, found := strings.Cut(strings.TrimSpace(param), "=")
				if found && strings.EqualFold(name, "for") {
					hops = append(hops, value)
					break
				}
			}
		}
	}
	return hops
}

// parseAddress turns a hop value into an address: quoted or bracketed IPv6,
// optional port, v4-mapped IPv6 folded to plain IPv4 by net.ParseIP. Anything
// else - "unknown", "_hidden", an IPv6 zone - parses to nil.
func parseAddress(value string) net.IP {
	value = strings.Trim(strings.TrimSpace(value), `"`)
	if value == "" {
		return nil
	}
	if strings.HasPrefix(value, "[") {
		if end := strings.IndexByte(value, ']'); end > 0 {
			value = value[1:end]
		}
	}
	if host, _, err := net.SplitHostPort(value); err == nil {
		value = host
	}
	return net.ParseIP(value)
}
