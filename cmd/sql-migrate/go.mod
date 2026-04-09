module github.com/therootcompany/golib/cmd/sql-migrate/v2

go 1.26.1

require (
	github.com/jackc/pgx/v5 v5.9.1
	github.com/therootcompany/golib/database/sqlmigrate v1.0.0
	github.com/therootcompany/golib/database/sqlmigrate/shmigrate v0.0.0
)

require (
	github.com/jackc/pgpassfile v1.0.0 // indirect
	github.com/jackc/pgservicefile v0.0.0-20240606120523-5a60cdf6a761 // indirect
	golang.org/x/text v0.29.0 // indirect
)

replace (
	github.com/therootcompany/golib/database/sqlmigrate => ../../database/sqlmigrate
	github.com/therootcompany/golib/database/sqlmigrate/shmigrate => ../../database/sqlmigrate/shmigrate
)
