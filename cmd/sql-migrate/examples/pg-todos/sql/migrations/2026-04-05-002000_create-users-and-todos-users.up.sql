-- create-users-and-todos-users (up)

CREATE TABLE users (
   id CHAR(8) PRIMARY KEY,
   name VARCHAR(100) NOT NULL,
   email VARCHAR(254) NOT NULL UNIQUE,
   created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE todos_users (
   todo_id CHAR(8) NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
   user_id CHAR(8) NOT NULL REFERENCES users(id) ON DELETE CASCADE,
   PRIMARY KEY (todo_id, user_id)
);

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('2026-04-05-002000_create-users-and-todos-users', 'b2c3d4e5');
