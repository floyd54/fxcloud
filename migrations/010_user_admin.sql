-- 010_user_admin.sql: administrator role for the user administration UI.
--
-- `is_admin` marks accounts that may open the "user administration" dialog in
-- the web UI (frontend/assets/app.js) and call the /api/admin endpoints. Every
-- read path that touches it goes through src/web/middleware.rs (AdminUser).
--
-- The column defaults to 0, and the UPDATE promotes the oldest account that
-- is already active. On an existing instance that is the bootstrap account -
-- the operator's own first login (see the is_active bootstrap in
-- src/db/user.rs insert_user), which was always created active and has been
-- the de-facto administrator ever since, just without the flag. A fresh
-- instance has no users yet; there the flag is set by the same insert_user
-- path (COUNT(*) == 0) when the first account is created.
--
-- The UPDATE must also run on a fresh database, so it is part of the guarded
-- migration rather than a one-shot script. It is written as a subquery on
-- MIN(id) instead of "ORDER BY ... LIMIT" because SQLite only honours the
-- latter when built with SQLITE_ENABLE_UPDATE_DELETE_LIMIT, which is not
-- guaranteed.
ALTER TABLE users ADD COLUMN is_admin INTEGER NOT NULL DEFAULT 0;

UPDATE users
   SET is_admin = 1
 WHERE id = (SELECT MIN(id) FROM users WHERE is_active = 1);
