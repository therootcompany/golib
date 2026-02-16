package internal

import (
	"net/http"
	"net/http/httputil"
	"net/url"
)

func ProxyToOtherAPI(proxyTarget string) http.Handler {
	target, _ := url.Parse(proxyTarget)
	proxy := &httputil.ReverseProxy{
		Rewrite: func(r *httputil.ProxyRequest) {
			// r.SetXForwarded() // these are trusted from the tls-terminating proxy
			r.SetURL(target)
			r.Out.Host = r.In.Host
		},
	}
	return proxy
}
