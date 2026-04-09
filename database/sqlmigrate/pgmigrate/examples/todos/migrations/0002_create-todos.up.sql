CREATE TABLE todos (
    id CHAR(8) PRIMARY KEY,
    title VARCHAR(255) NOT NULL,
    done BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
);

INSERT INTO _migrations (name, id) VALUES ('0002_create-todos', 'a1b2c3d4');
