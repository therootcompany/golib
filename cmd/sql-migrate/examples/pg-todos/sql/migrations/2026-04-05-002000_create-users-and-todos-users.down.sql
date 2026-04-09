-- create-users-and-todos-users (down)

DROP TABLE IF EXISTS todos_users;
DROP TABLE IF EXISTS users;

-- leave this as the last line
DELETE FROM _migrations WHERE id = 'b2c3d4e5';
