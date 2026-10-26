-- Phase 3 (ENCRYPTION.md 5.5): one key envelope per share row.
--
-- Opaque to the server by design: the owner's browser seals the shared
-- source's key record to the grantee's public key (ECIES - ephemeral ECDH,
-- HKDF-SHA-256, AES-256-GCM), the grantee's browser opens it again with
-- their private key. The server stores and forwards the blob; it can
-- neither read nor produce it. NULL for shares of plaintext sources, which
-- need no key exchange at all.
ALTER TABLE shares ADD COLUMN envelope TEXT;
