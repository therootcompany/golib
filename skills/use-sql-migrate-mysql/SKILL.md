---
name: use-sql-migrate-mysql
description: MySQL and MariaDB migrations with sql-migrate and mymigrate. Use when setting up MySQL/MariaDB migrations, configuring multiStatements, or MY_CNF credentials.
depends: [use-sqlmigrate]
---

## CLI setup

```sh
# MariaDB
sql-migrate -d ./sql/migrations/ init --sql-command mariadb

# MySQL
sql-migrate -d ./sql/migrations/ init --sql-command mysql
```

## Environment

```sh
# .env
MY_URL='user:pass@tcp(localhost:3306)/mydb?multiStatements=true&parseTime=true'
MY_CNF='./my.cnf'
```

MUST: Include `multiStatements=true` in the DSN. mymigrate validates this on first exec and returns an error if missing.

## Credentials file (for CLI)

The CLI uses `--defaults-extra-file` to avoid passwords in command args:

```ini
# my.cnf
[client]
host=localhost
port=3306
database=mydb
user=appuser
password=secret
```

## Go library

```go
import (
    "database/sql"

    _ "github.com/go-sql-driver/mysql"
    "github.com/therootcompany/golib/database/sqlmigrate"
    "github.com/therootcompany/golib/database/sqlmigrate/mymigrate"
)

db, err := sql.Open("mysql", myURL)
conn, err := db.Conn(ctx)
defer func() { _ = conn.Close() }()

runner := mymigrate.New(conn)
applied, err := sqlmigrate.Latest(ctx, runner, scripts)
```

## SQL dialect notes

- DDL statements (CREATE/ALTER/DROP) auto-commit in MySQL — partial failures possible on multi-statement down migrations
- `INSERT IGNORE` for idempotent seeds (not `ON CONFLICT`)
- `NOW()` for current timestamp
- String concatenation: `CONCAT(id, CHAR(9), name)` (used by sync query)
- `ON UPDATE CURRENT_TIMESTAMP` for auto-updated timestamps
- Error 1146 = table doesn't exist (handled automatically by mymigrate)
