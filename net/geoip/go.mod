module github.com/therootcompany/golib/net/geoip

go 1.26.0

require (
	github.com/oschwald/geoip2-golang v1.13.0
	github.com/therootcompany/golib/net/httpcache v0.0.0
)

require (
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
)

replace github.com/therootcompany/golib/net/httpcache => ../httpcache
