-- create-folders-and-folders-todos (down)

DROP TABLE IF EXISTS folders_todos;
DROP TABLE IF EXISTS folders;

-- leave this as the last line
DELETE FROM _migrations WHERE id = 'c3d4e5f6';
