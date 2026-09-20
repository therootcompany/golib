-- init-migrations (up)

CREATE TABLE IF NOT EXISTS _migrations (
   id CHAR(8) PRIMARY KEY,
   name VARCHAR(80) UNIQUE,
   applied_at TEXT DEFAULT (datetime('now'))
);

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('0001-01-01-001000_init-migrations', '00000001');
