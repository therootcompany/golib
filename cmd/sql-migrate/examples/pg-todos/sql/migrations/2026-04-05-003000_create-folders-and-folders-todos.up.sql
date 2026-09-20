-- create-folders-and-folders-todos (up)

CREATE TABLE folders (
   id CHAR(8) PRIMARY KEY,
   name VARCHAR(100) NOT NULL,
   created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE folders_todos (
   folder_id CHAR(8) NOT NULL REFERENCES folders(id) ON DELETE CASCADE,
   todo_id CHAR(8) NOT NULL REFERENCES todos(id) ON DELETE CASCADE,
   PRIMARY KEY (folder_id, todo_id)
);

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('2026-04-05-003000_create-folders-and-folders-todos', 'c3d4e5f6');
