module github.com/therootcompany/golib/cmd/form2mail

go 1.26.0

require (
	github.com/joho/godotenv v1.5.1
	github.com/therootcompany/golib/net/formmailer v0.0.0
	github.com/therootcompany/golib/net/geoip v0.0.0
	github.com/therootcompany/golib/net/gitshallow v0.0.0
	github.com/therootcompany/golib/net/httpcache v0.0.0
	github.com/therootcompany/golib/net/ipcohort v0.0.0
	github.com/therootcompany/golib/sync/dataset v0.0.0
	golang.org/x/term v0.39.0
)

require (
	github.com/oschwald/geoip2-golang v1.13.0 // indirect
	github.com/oschwald/maxminddb-golang v1.13.0 // indirect
	golang.org/x/sys v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
)

replace (
	github.com/therootcompany/golib/net/formmailer v0.0.0 => ../../net/formmailer
	github.com/therootcompany/golib/net/geoip v0.0.0 => ../../net/geoip
	github.com/therootcompany/golib/net/gitshallow v0.0.0 => ../../net/gitshallow
	github.com/therootcompany/golib/net/httpcache v0.0.0 => ../../net/httpcache
	github.com/therootcompany/golib/net/ipcohort v0.0.0 => ../../net/ipcohort
	github.com/therootcompany/golib/sync/dataset v0.0.0 => ../../sync/dataset
)
