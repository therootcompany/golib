CREATE TABLE IF NOT EXISTS _migrations (
    id CHAR(8) PRIMARY KEY,
    name VARCHAR(80) NULL UNIQUE,
    applied_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO _migrations (name, id) VALUES ('0001_init-migrations', '00000001');
