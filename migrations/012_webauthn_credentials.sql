-- 012_webauthn_credentials.sql: passkeys (WebAuthn/FIDO2).
--
-- One row per registered device. The server keeps only what verification
-- needs: the credential id (the RP-scoped handle every assertion is looked
-- up by), the COSE public key, the signature counter for clone detection,
-- and display metadata. The private half never leaves the authenticator.
--
-- A passkey is a *login* credential only: it opens a web session like the
-- password does and has no role in the client-side key hierarchy, where the
-- storage passphrase of ENCRYPTION.md 5.7 stays in charge.
--
-- The migration number skips 011: that slot belonged to the withdrawn
-- passphrase-login round (reverted in f9aa1d9), and leaving the number open
-- keeps `git log -- migrations/011*` honest about what happened.
--
-- `credential_id` is UNIQUE because it is the lookup key of every
-- assertion; a duplicate would make sign-in ambiguous between two devices.
-- `label` is the device name the settings dialog lists (renameable, the
-- routes default it to "Passkey").
CREATE TABLE IF NOT EXISTS webauthn_credentials (
    id            INTEGER PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    credential_id BLOB NOT NULL UNIQUE,
    public_key    BLOB NOT NULL,    -- COSE_Key (EC2/ES256) in CBOR
    sign_count    INTEGER NOT NULL DEFAULT 0,
    transports    TEXT NOT NULL DEFAULT '',  -- comma list: usb,nfc,internal,hybrid
    label         TEXT NOT NULL,
    created_at    TEXT NOT NULL,
    last_used_at  TEXT
);

-- Device listing and the per-account exclude/allow lists read one user's
-- rows; without the index every ceremony round-trip would scan the table.
CREATE INDEX IF NOT EXISTS idx_webauthn_credentials_user
    ON webauthn_credentials(user_id);
