-- add-todo-fields (up)

ALTER TABLE todos ADD COLUMN completed_at TIMESTAMP;
ALTER TABLE todos ADD COLUMN priority INTEGER NOT NULL DEFAULT 0;

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('2026-04-05-004000_add-todo-fields', 'd4e5f6a7');
