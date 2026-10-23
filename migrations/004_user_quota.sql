-- Per-account storage quota.
--
-- `DEFAULT` matters twice: accounts that already exist when this migration
-- runs are backfilled with the default by SQLite, and accounts created
-- afterwards never set the column (see src/db/user.rs::insert_user), so every
-- account starts out with 1 GiB. Raise or lower a single account directly in
-- the database until there is a user-administration UI:
--   UPDATE users SET quota_bytes = 2147483648 WHERE username = '…';
ALTER TABLE users ADD COLUMN quota_bytes INTEGER NOT NULL DEFAULT 1073741824;
