module github.com/therootcompany/golib/net/formmailer

go 1.26.5

require (
	github.com/therootcompany/golib/net/geoip v0.5.3
	github.com/therootcompany/golib/net/gitshallow v0.9.3
	github.com/therootcompany/golib/net/ipcohort v0.9.0
	github.com/therootcompany/golib/sync/dataset v0.5.0
	golang.org/x/time v0.15.0
)

require (
	github.com/oschwald/geoip2-golang v1.13.0 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	github.com/therootcompany/golib/https v0.9.0 // indirect
	github.com/therootcompany/golib/net/httpcache v0.5.1 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.45.0 // indirect
)

replace github.com/therootcompany/golib/net/geoip v0.5.3 => ../geoip
