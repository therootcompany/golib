package https

import (
	"cmp"
	"net"
	"net/http"
	"time"
)

// NewSlowDialer allows more time for DNS, Happy Eyeballs, and high-latency links.
func NewSlowDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   15 * time.Second,
		KeepAlive: 30 * time.Second,
	}
}

// NewSlowTransport is tolerant of slow networks and sluggish servers.
// Still protects against completely hung connections.
func NewSlowTransport() *http.Transport {
	dialer := NewSlowDialer()
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       dialer.DialContext,
		ForceAttemptHTTP2: true,

		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 20,
		MaxConnsPerHost:     100,
		IdleConnTimeout:     89 * time.Second,

		TLSHandshakeTimeout:   15 * time.Second,
		ResponseHeaderTimeout: 59 * time.Second,
		ExpectContinueTimeout: 2 * time.Second,
	}
}

// NewSlowClient is for requests that may legitimately take a long time.
// Prefer request-level context timeouts when you need finer control.
func NewSlowClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   cmp.Or(timeout, 89*time.Second),
		Transport: NewSlowTransport(),
	}
}
