-- Groups and group folders (concepts/groups.md section 3).
-- The concept says 015; versioning took 015/016, so groups land as 017.

-- A group is a storage principal of its own: its own quota, managed
-- membership, and (from here on) every file row it pays for.
CREATE TABLE IF NOT EXISTS groups (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    quota_bytes INTEGER NOT NULL,          -- operator-set
    created_by  INTEGER REFERENCES users(id),
    created_at  TEXT NOT NULL
);

-- One role per membership, applying to all of the group's folders:
-- 0 = member, 1 = manager (concepts/groups.md section 4).
CREATE TABLE IF NOT EXISTS group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     INTEGER NOT NULL,
    added_at TEXT NOT NULL,
    UNIQUE(group_id, user_id)
);

-- E2EE: one envelope per (top-level group folder, member); children follow
-- the parent-wraps-child hierarchy as everywhere else (section 5).
CREATE TABLE IF NOT EXISTS group_keys (
    file_id    INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    envelope   TEXT NOT NULL,              -- base64 ECIES, <= 8192 chars
    created_at TEXT NOT NULL,
    UNIQUE(file_id, user_id)
);

-- Attribution: whose storage and whose quota pays for this row. NULL is a
-- personal row; the creator stays in owner_id for the audit either way.
ALTER TABLE files ADD COLUMN owner_group_id INTEGER REFERENCES groups(id);

CREATE INDEX IF NOT EXISTS idx_files_group ON files(owner_group_id);
CREATE INDEX IF NOT EXISTS idx_group_members_user ON group_members(user_id);

-- Sibling names inside one group's tree are unique no matter which member
-- created the rows: the personal index (001) keys on owner_id, and in a group
-- tree the creators differ, so it cannot catch a duplicate name two members
-- both typed (concepts/groups.md section 3). Group top-level folders are
-- parentless rows too, so this also keeps one group from naming two of its
-- roots alike; twins across groups or against a personal root stay possible
-- and are told apart by their badge.
CREATE UNIQUE INDEX IF NOT EXISTS idx_files_group_sibling
    ON files(owner_group_id, IFNULL(parent_id, -1), name)
    WHERE owner_group_id IS NOT NULL;
