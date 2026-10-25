-- The entry's key wrapped with the parent folder's key (ENCRYPTION.md 5.4).
-- NULL for plaintext entries. Server-opaque, but returned to whoever the
-- existing share/read logic already authorizes - it is useless without the
-- parent key, which only the client can unwrap.
--
-- Separate migration from `006_keys` with its own guard, because SQLite has
-- no `ALTER TABLE ... ADD COLUMN IF NOT EXISTS`: two columns in one batch
-- guarded by the first would be skipped forever if only the first had landed.
ALTER TABLE files ADD COLUMN enc_key BLOB;
