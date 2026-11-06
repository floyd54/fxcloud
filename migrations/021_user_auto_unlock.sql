-- The auto-unlock switch (ENCRYPTION.md 5.7, phase 4 persistence of
-- DECISION 7): when set, a browser that holds this account's device
-- blob opens the key row without the storage passphrase. The switch
-- travels with the account; the blob itself never leaves the browser,
-- and off (0) keeps the v1 behaviour: memory-only keys per tab.
ALTER TABLE users ADD COLUMN auto_unlock INTEGER NOT NULL DEFAULT 0;
