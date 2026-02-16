-- add-blobs-table (down)
DROP TABLE IF EXISTS "blobs";

DELETE FROM _migrations WHERE id = '45249baf';
