module github.com/therootcompany/golib/cmd/smsapid

go 1.25.0

require (
	github.com/go-chi/chi/v5 v5.2.5
	github.com/joho/godotenv v1.5.1
	github.com/jszwec/csvutil v1.10.0
	github.com/simonfrey/jsonl v0.0.0-20240904112901-935399b9a740
	github.com/therootcompany/golib/auth v1.1.1
	github.com/therootcompany/golib/auth/csvauth v1.2.3
	github.com/therootcompany/golib/colorjson v1.0.1
	github.com/therootcompany/golib/http/androidsmsgateway v0.0.0-20260223054429-c8f26aca7c6d
	github.com/therootcompany/golib/http/middleware/v2 v2.0.0
)

require (
	github.com/fatih/color v1.18.0 // indirect
	github.com/mattn/go-colorable v0.1.13 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	golang.org/x/crypto v0.42.0 // indirect
	golang.org/x/sys v0.36.0 // indirect
)

replace (
	github.com/therootcompany/golib/auth => ../../auth
	github.com/therootcompany/golib/auth/csvauth => ../../auth/csvauth
	github.com/therootcompany/golib/http/androidsmsgateway => ../../http/androidsmsgateway
	github.com/therootcompany/golib/http/middleware/v2 => ../../http/middleware
)
