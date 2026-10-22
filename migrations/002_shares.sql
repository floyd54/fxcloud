-- Sharing: one row grants a user (grantee) access to one of the owner's
-- entries. The share is surfaced in the grantee's root under `display_name`
-- and resolution "crosses" into the owner's subtree from there.

CREATE TABLE IF NOT EXISTS shares (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    source_id    INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    owner_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    grantee_id   INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    display_name TEXT    NOT NULL,
    permissions  INTEGER NOT NULL,
    created_at   TEXT    NOT NULL,
    UNIQUE(source_id, grantee_id)
);

CREATE INDEX IF NOT EXISTS idx_shares_grantee ON shares(grantee_id);
CREATE INDEX IF NOT EXISTS idx_shares_owner   ON shares(owner_id);
CREATE INDEX IF NOT EXISTS idx_shares_source  ON shares(source_id);
