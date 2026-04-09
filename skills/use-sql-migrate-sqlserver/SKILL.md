---
name: use-sql-migrate-sqlserver
description: SQL Server migrations with sql-migrate and msmigrate. Use when setting up SQL Server migrations, configuring sqlcmd, TDS 8.0 encryption, or SQLCMD environment variables.
depends: [use-sqlmigrate]
---

## CLI setup

```sh
sql-migrate -d ./sql/migrations/ init --sql-command sqlcmd
```

Requires the modern sqlcmd (go-mssqldb), not the legacy ODBC version.
Install: `brew install sqlcmd` (macOS), `winget install sqlcmd` (Windows).

## Environment

```sh
# .env — for Go app (DSN)
MS_URL='sqlserver://sa:Password@localhost:1433?database=mydb'

# .env — for sqlcmd CLI (reads these automatically)
SQLCMDSERVER='localhost'
SQLCMDDATABASE='mydb'
SQLCMDUSER='sa'
SQLCMDPASSWORD='secret'
```

SQLCMDSERVER formats:
- `localhost` — default instance
- `'localhost\SQLEXPRESS'` — named instance (quote the backslash)
- `'localhost,1433'` — host and port

## TDS 8.0 encryption

Default uses `--encrypt-connection strict` (TLS-first with ALPN `tds/8.0` and SNI).

For local dev without TLS:

```sh
sql-migrate -d ./sql/migrations/ init \
    --sql-command 'sqlcmd --exit-on-error --headers -1 --trim-spaces --encrypt-connection disable --input-file %s'
```

## Go library

```go
import (
    "database/sql"

    _ "github.com/microsoft/go-mssqldb"
    "github.com/therootcompany/golib/database/sqlmigrate"
    "github.com/therootcompany/golib/database/sqlmigrate/msmigrate"
)

db, err := sql.Open("sqlserver", msURL)
conn, err := db.Conn(ctx)
defer func() { _ = conn.Close() }()

runner := msmigrate.New(conn)
applied, err := sqlmigrate.Latest(ctx, runner, scripts)
```

## SQL dialect notes

- `IF OBJECT_ID('table', 'U') IS NULL CREATE TABLE ...` instead of `CREATE TABLE IF NOT EXISTS`
- `SYSDATETIME()` instead of `CURRENT_TIMESTAMP` for DATETIME2 defaults
- `DATETIME2` for timestamps (not `TIMESTAMP` — that's a row version in SQL Server)
- `@p1`, `@p2` for parameterized queries in Go (not `?`)
- Dropping columns with defaults requires dropping the default constraint first:

```sql
DECLARE @constraint NVARCHAR(256);
SELECT @constraint = name FROM sys.default_constraints
    WHERE parent_object_id = OBJECT_ID('todos')
    AND parent_column_id = (SELECT column_id FROM sys.columns
        WHERE object_id = OBJECT_ID('todos') AND name = 'priority');
IF @constraint IS NOT NULL
    EXEC('ALTER TABLE todos DROP CONSTRAINT ' + @constraint);
ALTER TABLE todos DROP COLUMN priority;
```

- `IF NOT EXISTS (SELECT 1 FROM table WHERE ...) INSERT ...` for idempotent seeds
- String concatenation: `id + CHAR(9) + name` (used by sync query)
- Error 208 = invalid object name (table doesn't exist, handled by msmigrate)

## SSH tunnel for remote dev

```sh
ssh -o ProxyCommand='sclient --alpn ssh %h' -fnNT \
    -L 21433:localhost:1433 \
    tls-<ip>.a.bnna.net
```

Then set `MS_URL='sqlserver://sa:pass@localhost:21433?database=todos'`.
