-- add-indexes-and-constraints (down)

ALTER TABLE todos DROP CONSTRAINT IF EXISTS chk_todo_status;
DROP INDEX IF EXISTS idx_todos_completed_at;
DROP INDEX IF EXISTS idx_folders_todos_todo_id;
DROP INDEX IF EXISTS idx_todos_users_user_id;

-- leave this as the last line
DELETE FROM _migrations WHERE id = 'e5f6a7b8';
