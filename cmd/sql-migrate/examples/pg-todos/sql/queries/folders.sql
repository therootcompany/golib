-- name: FolderCreate :one
INSERT INTO folders (id, name)
VALUES (sqlc.arg('id'), sqlc.arg('name'))
RETURNING id, name, created_at;

-- name: FolderList :many
SELECT id, name, created_at
FROM folders
ORDER BY name ASC;

-- name: FolderDelete :exec
DELETE FROM folders WHERE id = sqlc.arg('id');

-- name: FolderAddTodo :exec
INSERT INTO folders_todos (folder_id, todo_id)
VALUES (sqlc.arg('folder_id'), sqlc.arg('todo_id'));

-- name: FolderRemoveTodo :exec
DELETE FROM folders_todos
WHERE folder_id = sqlc.arg('folder_id')
  AND todo_id = sqlc.arg('todo_id');

-- name: FolderGetByName :one
SELECT id, name, created_at
FROM folders
WHERE name = sqlc.arg('name');

-- name: FolderTodos :many
SELECT t.id, t.title, t.status, t.completed_at, t.priority, t.created_at, t.updated_at
FROM todos t
JOIN folders_todos ft ON ft.todo_id = t.id
WHERE ft.folder_id = sqlc.arg('folder_id')
ORDER BY t.priority DESC, t.created_at ASC;
