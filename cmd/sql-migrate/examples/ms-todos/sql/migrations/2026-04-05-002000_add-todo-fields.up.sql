-- add-todo-fields (up)

ALTER TABLE todos ADD completed_at DATETIME2 NULL;
ALTER TABLE todos ADD priority INT NOT NULL DEFAULT 0;

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('2026-04-05-002000_add-todo-fields', 'd4e5f6a7');
