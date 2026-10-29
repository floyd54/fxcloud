-- Session bookkeeping for the management UI and sliding renewal
-- (Audit.md F4).
--
-- `sid` is the handle the API and the settings page show and revoke by:
-- a session's primary key IS the secret token, and an endpoint that
-- listed tokens would defeat the HttpOnly cookie - any script that can
-- read the listing could read every session's credential. `sid` carries
-- no power of its own: every query that uses it is scoped to the
-- caller's own user_id, so a sid is a label, not a key.
ALTER TABLE sessions ADD COLUMN sid TEXT;

-- The device the session was created on, shown next to the timestamps so
-- an incident listing answers "which of these is the one I do not
-- recognise?" The string is capped at capture time; an empty value (all
-- pre-existing rows) simply shows no device line.
ALTER TABLE sessions ADD COLUMN user_agent TEXT NOT NULL DEFAULT '';

-- Sliding renewal writes at most once per window (see Db::session_touch).
-- The default of '' is overwritten for every pre-existing row below; an
-- empty value reads as older than any cutoff, so a row the backfill
-- missed would renew on its next request instead of never expiring.
ALTER TABLE sessions ADD COLUMN last_seen_at TEXT NOT NULL DEFAULT '';

UPDATE sessions SET sid = lower(hex(randomblob(16))) WHERE sid IS NULL;
UPDATE sessions SET last_seen_at = created_at WHERE last_seen_at = '';

CREATE UNIQUE INDEX IF NOT EXISTS idx_sessions_sid ON sessions(sid);
