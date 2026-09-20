-- name: TodoCreate :one
INSERT INTO todos (id, title, status)
VALUES (sqlc.arg('id'), sqlc.arg('title'), 'pending')
RETURNING id, title, status, completed_at, priority, created_at, updated_at;

-- name: TodoList :many
SELECT id, title, status, completed_at, priority, created_at, updated_at
FROM todos
ORDER BY priority DESC, created_at ASC;

-- name: TodoListUnfoldered :many
SELECT id, title, status, completed_at, priority, created_at, updated_at
FROM todos
WHERE id NOT IN (SELECT todo_id FROM folders_todos)
ORDER BY priority DESC, created_at ASC;

-- name: TodoMarkDone :one
UPDATE todos
SET status = 'done',
    completed_at = CURRENT_TIMESTAMP,
    updated_at = CURRENT_TIMESTAMP
WHERE id = sqlc.arg('id')
RETURNING id, title, status, completed_at, priority, created_at, updated_at;

-- name: TodoDelete :exec
DELETE FROM todos WHERE id = sqlc.arg('id');
