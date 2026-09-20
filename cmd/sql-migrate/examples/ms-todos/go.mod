module github.com/therootcompany/golib/cmd/sql-migrate/examples/ms-todos

go 1.26.1

require (
	github.com/joho/godotenv v1.5.1
	github.com/microsoft/go-mssqldb v1.9.8
	github.com/therootcompany/golib/database/sqlmigrate v1.0.2
	github.com/therootcompany/golib/database/sqlmigrate/msmigrate v1.0.2
)

require (
	github.com/golang-sql/civil v0.0.0-20220223132316-b832511892a9 // indirect
	github.com/golang-sql/sqlexp v0.1.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/shopspring/decimal v1.4.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/text v0.34.0 // indirect
)

replace (
	github.com/therootcompany/golib/database/sqlmigrate => ../../../../database/sqlmigrate
	github.com/therootcompany/golib/database/sqlmigrate/msmigrate => ../../../../database/sqlmigrate/msmigrate
)
