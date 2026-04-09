module github.com/therootcompany/golib/cmd/sql-migrate/v2

go 1.26.1

require (
	github.com/therootcompany/golib/database/sqlmigrate v1.0.2
	github.com/therootcompany/golib/database/sqlmigrate/shmigrate v0.0.0
)

replace (
	github.com/therootcompany/golib/database/sqlmigrate => ../../database/sqlmigrate
	github.com/therootcompany/golib/database/sqlmigrate/shmigrate => ../../database/sqlmigrate/shmigrate
)
