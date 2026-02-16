-- name: BlobsAll :many
SELECT *
FROM blobs
ORDER BY key;
