-- Phase4 recovery UX (ENCRYPTION.md 5.7): the recovery key, on demand.
-- The key is stored wrapped under the passphrase KEK - a passphrase
-- holder can already unwrap the ARK, so this adds no new power, it only
-- makes the once-shown key recoverable from the secret the user has.
-- NULL for rows set up before this column: those answer "issue a new
-- key", which fills it.
ALTER TABLE user_keys ADD COLUMN wrapped_recovery BLOB;
