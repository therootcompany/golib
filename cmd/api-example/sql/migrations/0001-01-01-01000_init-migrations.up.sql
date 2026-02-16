-- Config variables for sql-migrate (do not delete)
-- sql_command: psql "$PG_URL" -v ON_ERROR_STOP=on -A -t --file %s
-- migrations_log: ./db/paperdb-migrations.log
--

CREATE TABLE IF NOT EXISTS _migrations (
   id CHAR(8) PRIMARY KEY,
   name VARCHAR(80) UNIQUE NOT NULL,
   applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- note: to enable text-based tools to grep and sort we put 'name' before 'id'
--       grep -r 'INSERT INTO _migrations' ./sql/migrations/ | cut -d':' -f2 | sort
INSERT INTO _migrations (name, id) VALUES ('0001-01-01-01000_init-migrations', '00000001');
