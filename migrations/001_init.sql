-- fxcloud initial schema

CREATE TABLE IF NOT EXISTS users (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT    NOT NULL UNIQUE COLLATE NOCASE,
    password_hash TEXT    NOT NULL,
    display_name  TEXT    NOT NULL,
    created_at    TEXT    NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
    id         TEXT    PRIMARY KEY,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT    NOT NULL,
    expires_at TEXT    NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);

CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    owner_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    parent_id   INTEGER REFERENCES files(id) ON DELETE CASCADE,
    name        TEXT    NOT NULL,
    is_dir      INTEGER NOT NULL DEFAULT 0,
    size        INTEGER NOT NULL DEFAULT 0,
    mime        TEXT,
    created_at  TEXT    NOT NULL,
    modified_at TEXT    NOT NULL
);

-- A name must be unique among siblings under the same parent for a given owner.
-- NULL parents are treated as distinct per-owner roots by matching owner_id too.
CREATE UNIQUE INDEX IF NOT EXISTS idx_files_sibling_unique
    ON files(owner_id, IFNULL(parent_id, -1), name);

CREATE INDEX IF NOT EXISTS idx_files_parent ON files(parent_id);
