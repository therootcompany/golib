module github.com/therootcompany/golib/net/formmailer

go 1.26.0

require (
	github.com/therootcompany/golib/net/geoip v0.0.0
	github.com/therootcompany/golib/net/ipcohort v0.0.0
	github.com/therootcompany/golib/sync/dataset v0.0.0
	golang.org/x/time v0.15.0
)

require (
	github.com/oschwald/geoip2-golang v1.13.0 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	golang.org/x/sys v0.20.0 // indirect
)

replace github.com/therootcompany/golib/net/geoip => ../geoip

replace github.com/therootcompany/golib/net/ipcohort => ../ipcohort

replace github.com/therootcompany/golib/sync/dataset => ../../sync/dataset

replace github.com/therootcompany/golib/net/httpcache => ../httpcache
