package https

import (
	"net"
	"net/http"
	"time"
)

// NewDefaultDialer expects connections to be established quickly
func NewDefaultDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   4 * time.Second,
		KeepAlive: 25 * time.Second,
	}
}

// NewDefaultTransport expects quick tls termination, but allows for
// sluggish header response times (the server often doesn't know
// what headers to send until the response is nearly ready due to API
// calls, db queries, etc)
func NewDefaultTransport() *http.Transport {
	dialer := NewDefaultDialer()

	return &http.Transport{
		Proxy:             http.ProxyFromEnvironment,
		DialContext:       dialer.DialContext,
		ForceAttemptHTTP2: true,

		MaxConnsPerHost:     100,
		MaxIdleConnsPerHost: 10,
		MaxIdleConns:        100,
		IdleConnTimeout:     59 * time.Second, // less than 59s firewall timeouts

		TLSHandshakeTimeout:   4 * time.Second,
		ResponseHeaderTimeout: 20 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
}

// NewDefaultClient creates a new http client with reasonable and safe defaults
// for API services that are expected to connect and reply relatively quickly.
// DO NOT use for long streaming downloads or extremely slow APIs.
func NewDefaultClient() *http.Client {
	return &http.Client{
		Timeout:   25 * time.Second,
		Transport: NewDefaultTransport(),
	}
}
