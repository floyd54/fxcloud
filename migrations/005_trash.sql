-- Trash bin: deletions are marked, not removed. Only the trashed root row
-- carries the timestamp; its subtree stays intact underneath and comes back
-- as a whole on restore. The purge job hard-deletes roots older than the
-- retention window (rows via cascade, blobs separately).
ALTER TABLE files ADD COLUMN deleted_at TEXT;
CREATE INDEX IF NOT EXISTS idx_files_deleted ON files(deleted_at)
  WHERE deleted_at IS NOT NULL;

-- Sibling uniqueness must only cover live rows: a trashed entry keeps its
-- name while a new live file may already hold it again.
DROP INDEX IF EXISTS idx_files_sibling_unique;
CREATE UNIQUE INDEX IF NOT EXISTS idx_files_sibling_unique
  ON files(owner_id, IFNULL(parent_id, -1), name)
  WHERE deleted_at IS NULL;
