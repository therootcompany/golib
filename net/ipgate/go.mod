module github.com/therootcompany/golib/net/ipgate

go 1.26.0

require (
	github.com/therootcompany/golib/net/dnsresolver v0.0.0
	github.com/therootcompany/golib/net/gitshallow v0.0.0
	github.com/therootcompany/golib/net/ipcohort v0.0.0
)

require (
	github.com/miekg/dns v1.1.69 // indirect
	golang.org/x/mod v0.30.0 // indirect
	golang.org/x/net v0.47.0 // indirect
	golang.org/x/sync v0.20.0 // indirect
	golang.org/x/sys v0.38.0 // indirect
	golang.org/x/tools v0.39.0 // indirect
)

replace (
	github.com/therootcompany/golib/net/dnsresolver => ../dnsresolver
	github.com/therootcompany/golib/net/gitshallow => ../gitshallow
	github.com/therootcompany/golib/net/ipcohort => ../ipcohort
)
