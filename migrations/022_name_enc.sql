-- Names at rest (concepts/names.md, phase 6 S3): two columns, two
-- meanings that must not share one.
--
--   names_enc - the FOLDER flag: "the names of my children are blobs".
--     Set by the client's flag walk (PUT /api/files/nameenc), cascaded
--     to every descendant folder, inherited by creates and moves.
--   name_enc  - the ROW state: "this row's own name is a blob". Set by
--     the same cascade (everything below the flag, excluding the flag
--     row itself - its name belongs to its parent's context). Office,
--     public links, WebDAV MOVE and the share label guard read this.
ALTER TABLE files ADD COLUMN names_enc INTEGER NOT NULL DEFAULT 0;
ALTER TABLE files ADD COLUMN name_enc INTEGER NOT NULL DEFAULT 0;
