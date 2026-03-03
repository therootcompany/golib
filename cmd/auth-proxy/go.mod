module github.com/therootcompany/golib/cmd/auth-proxy

go 1.25.0

require (
	github.com/joho/godotenv v1.5.1
	github.com/therootcompany/golib/auth v1.1.1
	github.com/therootcompany/golib/auth/csvauth v1.2.4
)

require golang.org/x/crypto v0.42.0 // indirect

replace (
	github.com/therootcompany/golib/auth => ../../auth
	github.com/therootcompany/golib/auth/csvauth => ../../auth/csvauth
)
