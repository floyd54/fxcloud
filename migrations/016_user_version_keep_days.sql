-- Retention bound 2 of 2 (concepts/versioning.md, section 5): drop versions
-- older than this many days; 0 disables the bound. Guarded in db/mod.rs.
ALTER TABLE users ADD COLUMN version_keep_days INTEGER NOT NULL DEFAULT 180;
