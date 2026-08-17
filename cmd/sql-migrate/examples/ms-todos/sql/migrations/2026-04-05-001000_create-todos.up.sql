-- create-todos (up)

CREATE TABLE todos (
   id CHAR(8) PRIMARY KEY,
   title VARCHAR(255) NOT NULL,
   status VARCHAR(20) NOT NULL DEFAULT 'pending',
   created_at DATETIME2 NOT NULL DEFAULT SYSDATETIME(),
   updated_at DATETIME2 NOT NULL DEFAULT SYSDATETIME()
);

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('2026-04-05-001000_create-todos', 'a1b2c3d4');
