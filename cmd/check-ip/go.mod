module github.com/therootcompany/golib/cmd/check-ip

go 1.26.0

require (
	github.com/therootcompany/golib/net/geoip v0.5.0
	github.com/therootcompany/golib/net/gitshallow v0.9.1
	github.com/therootcompany/golib/net/httpcache v0.5.0
	github.com/therootcompany/golib/net/ipcohort v0.9.0
	github.com/therootcompany/golib/sync/dataset v0.5.0
)

replace github.com/therootcompany/golib/net/geoip => ../../net/geoip

require (
	github.com/oschwald/geoip2-golang v1.13.0 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)
