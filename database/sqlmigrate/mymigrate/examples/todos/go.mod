module github.com/therootcompany/golib/database/sqlmigrate/mymigrate/examples/todos

go 1.26.1

require (
	github.com/go-sql-driver/mysql v1.9.3
	github.com/therootcompany/golib/database/sqlmigrate v1.0.0
	github.com/therootcompany/golib/database/sqlmigrate/mymigrate v0.0.0
)

require filippo.io/edwards25519 v1.1.0 // indirect

replace (
	github.com/therootcompany/golib/database/sqlmigrate => ../../..
	github.com/therootcompany/golib/database/sqlmigrate/mymigrate => ../..
)
