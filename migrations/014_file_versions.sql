-- File version history (concepts/versioning.md): every content replacement
-- keeps the replaced bytes as a restorable previous version. The bytes are
-- not copied - a hardlink gives the outgoing blob a second name - so this
-- table carries only metadata.
--
-- `blob_created_at` is the version's on-disk key: time + random bytes, so
-- the link can be named before the row exists (a crash between the two
-- leaves an orphan file, never a row pointing at nothing), and two saves a
-- clock-tick apart cannot collide.
CREATE TABLE IF NOT EXISTS file_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    size            INTEGER NOT NULL,
    enc_version     INTEGER NOT NULL DEFAULT 0,
    author_id       INTEGER,             -- who saved this version
    blob_created_at TEXT NOT NULL,       -- part of the blob path (BlobRef)
    created_at      TEXT NOT NULL        -- when it was replaced FROM
);
CREATE INDEX IF NOT EXISTS idx_versions_file ON file_versions(file_id, created_at);
