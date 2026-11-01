-- Public links: anonymous bearer-token shares (concepts/public_links.md).
-- The concept says 018; that number is still free after groups took 017.

-- One row per link. The token itself is never stored - only
-- sha256(token) as hex - so a leaked DB dump yields no working links
-- (section 3). The token is 32 OsRng bytes, base64url without padding,
-- shown to the owner exactly once at creation.
CREATE TABLE IF NOT EXISTS public_links (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT    NOT NULL UNIQUE,   -- sha256 hex of the bearer token
    source_id       INTEGER NOT NULL REFERENCES files(id)   ON DELETE CASCADE,
    owner_id        INTEGER NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    permissions     INTEGER NOT NULL,          -- PERM_* mask, PERM_SHARE never set
    label           TEXT,                      -- owner's note, shown in their overview
    -- Expiry mode (section 3): 'rolling' (default) dies after expires_in_days
    -- *without use* and slides forward on every successful visitor call;
    -- 'fixed' is a hard deadline from creation that never moves; 'never'
    -- has no deadline at all (expires_at stays NULL).
    expiry_mode     TEXT    NOT NULL DEFAULT 'rolling',
    expires_in_days INTEGER,                   -- window (rolling) / lifetime (fixed); NULL iff 'never'
    created_at      TEXT    NOT NULL,
    expires_at      TEXT,                      -- effective deadline; NULL iff 'never'
    last_access_at  TEXT,
    download_count  INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_public_links_owner  ON public_links(owner_id);
CREATE INDEX IF NOT EXISTS idx_public_links_source ON public_links(source_id);
-- The sweep is an indexed scan on this column; the lazy per-access check
-- reaches the row through the UNIQUE token_hash anyway.
CREATE INDEX IF NOT EXISTS idx_public_links_expires ON public_links(expires_at)
    WHERE expires_at IS NOT NULL;
