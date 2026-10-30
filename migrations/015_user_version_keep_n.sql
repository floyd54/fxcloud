-- Retention bound 1 of 2 (concepts/versioning.md, section 5): keep at most
-- N versions per file; 0 disables the bound. Guarded in db/mod.rs - SQLite's
-- ALTER TABLE ADD COLUMN has no IF NOT EXISTS.
ALTER TABLE users ADD COLUMN version_keep_n INTEGER NOT NULL DEFAULT 20;
