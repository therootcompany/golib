module github.com/therootcompany/golib/auth/jwt/tests

go 1.25.0

require (
	github.com/golang-jwt/jwt/v5 v5.2.2
	github.com/therootcompany/golib/auth/jwt v0.0.0
)

replace github.com/therootcompany/golib/auth/jwt => ../
