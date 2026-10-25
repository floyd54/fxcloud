-- Client-side per-file encryption (ENCRYPTION.md, phase 1).
--
-- The server stores only what it cannot read: wrapped key material for the
-- account, and per entry the entry's own key wrapped with its parent's key.
-- Every blob below is opaque ciphertext as far as this process is concerned -
-- it is produced and consumed by the client, never by us.

-- One row per account, created once by POST /api/keys/setup. `public_key` is
-- published to other users (GET /api/keys/<username>); everything else stays
-- with the owner. `wrapped_ark_recovery` is required, not optional: under
-- DECISION 3 the login password and the storage secret are the same event,
-- so the recovery envelope is the only path left if it is forgotten.
CREATE TABLE IF NOT EXISTS user_keys (
    user_id               INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
    public_key            BLOB NOT NULL,   -- raw public key, suite id prefix
    private_key_wrapped   BLOB NOT NULL,   -- private key, wrapped under ARK
    wrapped_ark           BLOB NOT NULL,   -- ARK, wrapped under the passphrase KEK
    -- Root folder key, wrapped under the ARK (5.4): top-level entries are
    -- wrapped with it, and it lives here rather than in `files` because it
    -- belongs to the account, not to a row.
    wrapped_root_key      BLOB NOT NULL,
    wrapped_ark_recovery  BLOB NOT NULL,   -- ARK, wrapped under the recovery KEK
    kdf_salt              BLOB NOT NULL,   -- salt for the client-side Argon2id
    kdf_params            TEXT NOT NULL,   -- JSON: argon2id m/t/p + suite ids
    fingerprint           TEXT NOT NULL,   -- display + out-of-band compare
    created_at            TEXT NOT NULL,
    updated_at            TEXT NOT NULL
);

-- 0 = plaintext (the default, so every existing row keeps working unchanged),
-- 1 = "FXE1" chunked AES-GCM. Explicit on purpose: every read path branches
-- on this flag instead of sniffing bytes, and the UI badges the row.
ALTER TABLE files ADD COLUMN enc_version INTEGER NOT NULL DEFAULT 0;
