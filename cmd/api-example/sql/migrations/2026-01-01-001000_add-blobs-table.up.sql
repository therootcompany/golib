INSERT INTO _migrations (name, id) VALUES ('2026-01-01-001000_add-ai-blobs-table', '45249baf');

-- add-blobs-table (up)
CREATE TABLE "blobs" (
  "created_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "updated_at" TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  "key" VARCHAR(100) NOT NULL,
  "value" TEXT NOT NULL,
  PRIMARY KEY ("key")
)
