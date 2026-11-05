-- The folder write zone (ENCRYPTION.md phase4, section 10): a folder
-- flagged with enc_zone demands the key for new writes below it even
-- when the badge is off - "encrypt this subtree, keep the rest
-- WebDAV-compatible" without touching how the blanket badge behaves.
ALTER TABLE files ADD COLUMN enc_zone INTEGER NOT NULL DEFAULT 0;
