-- init-migrations (up)

IF OBJECT_ID('_migrations', 'U') IS NULL
CREATE TABLE _migrations (
   id CHAR(8) PRIMARY KEY,
   name VARCHAR(80) NULL UNIQUE,
   applied_at DATETIME2 DEFAULT SYSDATETIME()
);

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('0001-01-01-001000_init-migrations', '00000001');
