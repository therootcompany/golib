-- init-migrations (up)

CREATE TABLE IF NOT EXISTS _migrations (
   id CHAR(8) PRIMARY KEY,
   name VARCHAR(80) NULL UNIQUE,
   applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('0001-01-01-001000_init-migrations', '00000001');
