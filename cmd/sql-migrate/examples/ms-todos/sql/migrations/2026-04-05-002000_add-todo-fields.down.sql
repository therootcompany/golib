-- add-todo-fields (down)

-- SQL Server requires dropping default constraints before dropping columns
DECLARE @constraint NVARCHAR(256);
SELECT @constraint = name FROM sys.default_constraints
    WHERE parent_object_id = OBJECT_ID('todos')
    AND parent_column_id = (SELECT column_id FROM sys.columns
        WHERE object_id = OBJECT_ID('todos') AND name = 'priority');
IF @constraint IS NOT NULL
    EXEC('ALTER TABLE todos DROP CONSTRAINT ' + @constraint);

ALTER TABLE todos DROP COLUMN priority;
ALTER TABLE todos DROP COLUMN completed_at;

-- leave this as the last line
DELETE FROM _migrations WHERE id = 'd4e5f6a7';
