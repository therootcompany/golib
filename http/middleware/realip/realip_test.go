// Copyright 2026 AJ ONeal <aj@therootcompany.com> (https://therootcompany.com)
//
// To the extent possible under law, the author(s) has dedicated all copyright
// and related and neighboring rights to this software to the public domain
// worldwide. This software is distributed without any warranty.
//
// SPDX-License-Identifier: CC0-1.0

package realip

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

type realIPCase struct {
	name       string
	middleware func(http.Handler) http.Handler
	remoteAddr string
	headers    map[string]string
	repeated   map[string][]string
	wantRemote string
	wantPeer   string
}

func probeHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("X-Remote-Addr", r.RemoteAddr)
	if peer := PeerIP(r); peer != nil {
		w.Header().Set("X-Peer-Addr", peer.String())
	}
}

func run(t *testing.T, c realIPCase) {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, "/api/thing", nil)
	req.RemoteAddr = c.remoteAddr
	for key, value := range c.headers {
		req.Header.Set(key, value)
	}
	for key, values := range c.repeated {
		for _, value := range values {
			req.Header.Add(key, value)
		}
	}

	rec := httptest.NewRecorder()
	c.middleware(http.HandlerFunc(probeHandler)).ServeHTTP(rec, req)

	if got := rec.Header().Get("X-Remote-Addr"); got != c.wantRemote {
		t.Errorf("%s: r.RemoteAddr = %q, want %q", c.name, got, c.wantRemote)
	}
	if got := rec.Header().Get("X-Peer-Addr"); got != c.wantPeer {
		t.Errorf("%s: PeerIP(r) = %q, want %q", c.name, got, c.wantPeer)
	}
}

func TestTrust(t *testing.T) {
	trustLoopback := MustTrust("127.0.0.1")
	trustRouter := MustTrust("10.11.0.0/16")

	cases := []realIPCase{
		{
			name:       "nothing trusted: headers ignored",
			middleware: Trust(nil),
			remoteAddr: "127.0.0.1:3080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			wantRemote: "127.0.0.1:3080",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "client is the first hop not in the allow list",
			middleware: MustTrust("127.0.0.1", "198.51.100.5"),
			remoteAddr: "127.0.0.1:3080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7, 198.51.100.5"},
			wantRemote: "203.0.113.7",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "a CIDR prefix covers the proxy",
			middleware: trustRouter,
			remoteAddr: "10.11.2.55:3080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			wantRemote: "203.0.113.7",
			wantPeer:   "10.11.2.55",
		},
		{
			name:       "untrusted peer: a forwarding header is not evidence",
			middleware: trustRouter,
			remoteAddr: "203.0.113.9:443",
			headers:    map[string]string{"X-Forwarded-For": "10.11.0.1"},
			wantRemote: "203.0.113.9:443",
			wantPeer:   "203.0.113.9",
		},
		{
			name:       "every hop trusted: nearest known hop is the answer",
			middleware: MustTrust("10.0.0.0/8", "127.0.0.1"),
			remoteAddr: "127.0.0.1:8080",
			headers:    map[string]string{"X-Forwarded-For": "10.11.0.1, 10.11.0.2"},
			wantRemote: "10.11.0.1",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "Forwarded (RFC 7239) is the fallback, not the primary",
			middleware: MustTrust("203.0.113.5"),
			remoteAddr: "203.0.113.5:443",
			headers: map[string]string{
				"Forwarded":       `for="[2001:db8:0:1::5]";host=example.test;proto=https`,
				"X-Forwarded-For": "198.51.100.1",
			},
			wantRemote: "198.51.100.1",
			wantPeer:   "203.0.113.5",
		},
		{
			name:       "Forwarded parsed when there is no X-Forwarded-For",
			middleware: MustTrust("203.0.113.5", "198.51.100.9"),
			remoteAddr: "203.0.113.5:443",
			headers:    map[string]string{"Forwarded": `for="[2001:db8:0:1::5]", for=198.51.100.9`},
			wantRemote: "2001:db8:0:1::5",
			wantPeer:   "203.0.113.5",
		},
		{
			name:       "repeated header fields are treated as one comma-separated value",
			middleware: MustTrust("127.0.0.1", "198.51.100.5"),
			remoteAddr: "127.0.0.1:3080",
			repeated:   map[string][]string{"X-Forwarded-For": {"203.0.113.7", "198.51.100.5"}},
			wantRemote: "203.0.113.7",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "Forwarded: ports are stripped before the trust check",
			middleware: MustTrust("127.0.0.1", "198.51.100.9"),
			remoteAddr: "127.0.0.1:3080",
			headers:    map[string]string{"Forwarded": `for=203.0.113.7:47011, for=198.51.100.9`},
			wantRemote: "203.0.113.7",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "Forwarded: unknown and obfuscated hops stop the walk",
			middleware: MustTrust("127.0.0.1", "198.51.100.9"),
			remoteAddr: "127.0.0.1:3080",
			headers:    map[string]string{"Forwarded": `for=unknown, for="_hidden", for=203.0.113.7:47011, for=198.51.100.9`},
			wantRemote: "203.0.113.7",
			wantPeer:   "127.0.0.1",
		},
		{
			name: "CDN in front: the chain is still walked from the nearest hop",
			// visitor 203.0.113.1 -> proxyA 198.51.100.101 -> the edge (trusted peer)
			middleware: MustTrust("2a06:98c0:3600::103"),
			remoteAddr: "[2a06:98c0:3600::103]:443",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.1, 198.51.100.101"},
			wantRemote: "198.51.100.101",
			wantPeer:   "2a06:98c0:3600::103",
		},
		{
			name:       "explicit trust-all",
			middleware: MustTrust("0.0.0.0/0", "::/0"),
			remoteAddr: "198.51.100.7:443",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			wantRemote: "203.0.113.7",
			wantPeer:   "198.51.100.7",
		},
		{
			name:       "X-Real-IP when there is no chain",
			middleware: trustLoopback,
			remoteAddr: "127.0.0.1:3080",
			headers:    map[string]string{"X-Real-IP": "203.0.113.7"},
			wantRemote: "203.0.113.7",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "X-Real-IP: the last value wins",
			middleware: trustLoopback,
			remoteAddr: "127.0.0.1:3080",
			repeated:   map[string][]string{"X-Real-IP": {"203.0.113.9", "203.0.113.7"}},
			wantRemote: "203.0.113.7",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "trusted peer, no headers: the peer is the client",
			middleware: trustLoopback,
			remoteAddr: "127.0.0.1:3080",
			wantRemote: "127.0.0.1",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "a malformed hop stops the walk: fail closed to the peer",
			middleware: MustTrust("127.0.0.1", "192.0.2.1"),
			remoteAddr: "127.0.0.1:3080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7, 192.0.2.1, not-an-ip"},
			wantRemote: "127.0.0.1",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "an IPv6 zone is not a valid hop: fail closed to the peer",
			middleware: trustLoopback,
			remoteAddr: "127.0.0.1:3080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7, fe80::1%eth0"},
			wantRemote: "127.0.0.1",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "an IPv4-mapped IPv6 peer is folded to plain IPv4",
			middleware: trustLoopback,
			remoteAddr: "[::ffff:127.0.0.1]:3080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			wantRemote: "203.0.113.7",
			wantPeer:   "127.0.0.1",
		},
		{
			name:       "IPv6 peer trusted",
			middleware: MustTrust("2001:db8::1"),
			remoteAddr: "[2001:db8::1]:443",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			wantRemote: "203.0.113.7",
			wantPeer:   "2001:db8::1",
		},
		{
			name:       "Trust with already-parsed addresses",
			middleware: Trust([]net.IP{net.ParseIP("127.0.0.1")}),
			remoteAddr: "127.0.0.1:3080",
			headers:    map[string]string{"X-Forwarded-For": "203.0.113.7"},
			wantRemote: "203.0.113.7",
			wantPeer:   "127.0.0.1",
		},
		{
			name: "PeerIP without Trust in the chain reports the peer",
			middleware: func(next http.Handler) http.Handler {
				return http.HandlerFunc(probeHandler)
			},
			remoteAddr: "203.0.113.9:443",
			wantRemote: "203.0.113.9:443",
			wantPeer:   "203.0.113.9",
		},
	}

	for _, c := range cases {
		run(t, c)
	}
}

func TestMustTrustPanicsOnBadInput(t *testing.T) {
	defer func() {
		recovered := recover()
		if recovered == nil {
			t.Fatal("MustTrust accepted a bad CIDR")
		}
		if !strings.Contains(fmt.Sprintf("%v", recovered), "not a valid IP or CIDR") {
			t.Fatalf("panic message = %v", recovered)
		}
	}()

	_ = MustTrust("10.11.0.0/33")
}
