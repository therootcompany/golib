package https

import (
	"net"
	"net/http"
	"time"
)

// NewInternalDialer is aggressive because we expect very low network latency.
func NewInternalDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   2 * time.Second, // plenty for DNS + <200 ms RTT + Happy Eyeballs
		KeepAlive: 27 * time.Second,
	}
}

// NewInternalTransport prioritizes fast failure and high connection reuse
// for internal service-to-service traffic.
func NewInternalTransport() *http.Transport {
	dialer := NewInternalDialer()
	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       dialer.DialContext,
		ForceAttemptHTTP2: true,

		MaxIdleConns:        200,
		MaxIdleConnsPerHost: 50, // higher – few hosts, high concurrency
		MaxConnsPerHost:     200,
		IdleConnTimeout:     29 * time.Second,

		TLSHandshakeTimeout:   1 * time.Second,
		ResponseHeaderTimeout: 11 * time.Second, // still allows modest backend work
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// NewInternalClient is for internal APIs that should be fast.
// Do not use for slow batch jobs or external calls.
func NewInternalClient() *http.Client {
	return &http.Client{
		Timeout:   13 * time.Second,
		Transport: NewInternalTransport(),
	}
}
