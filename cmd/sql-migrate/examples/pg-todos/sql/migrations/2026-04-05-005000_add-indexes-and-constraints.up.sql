-- add-indexes-and-constraints (up)

CREATE INDEX idx_todos_users_user_id ON todos_users(user_id);
CREATE INDEX idx_folders_todos_todo_id ON folders_todos(todo_id);
CREATE INDEX idx_todos_completed_at ON todos(completed_at) WHERE completed_at IS NULL;
ALTER TABLE todos ADD CONSTRAINT chk_todo_status
   CHECK (status IN ('pending', 'in_progress', 'done'));

-- leave this as the last line
INSERT INTO _migrations (name, id) VALUES ('2026-04-05-005000_add-indexes-and-constraints', 'e5f6a7b8');
