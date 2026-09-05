-- add-todo-fields (down)

ALTER TABLE todos DROP COLUMN IF EXISTS priority;
ALTER TABLE todos DROP COLUMN IF EXISTS completed_at;

-- leave this as the last line
DELETE FROM _migrations WHERE id = 'd4e5f6a7';
