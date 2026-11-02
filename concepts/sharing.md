# Concept: sharing between accounts

Status: **implemented** (baseline feature; the share dialog's user
dropdown, batch sharing and the E2EE key envelope followed later).

## 1. Goal

Hand a file or folder to another account of the same instance with a
Nextcloud-style permission bitmask, enforced identically in the web UI
and over WebDAV, so a grantee sees and may change exactly the same
things in both.

## 2. The permission mask

| Bit   | Value | Meaning                                  |
| ----- | ----- | ---------------------------------------- |
| READ | 1     | View/download, list folder contents      |
| UPDATE | 2   | Overwrite content, rename/move, store a key record |
| CREATE | 4   | Add files/folders inside a shared folder |
| DELETE | 8   | Delete the item (or children of a folder) |
| SHARE | 16   | Reserved for re-sharing (not wired up)   |

The default grant is read + update + create + delete. The dialog offers
the first four as checkboxes; the fifth box is reserved.

## 3. How a grant reaches the grantee

- Shares are per-entry (`shares(source_id, owner_id, grantee_id,
  permissions, envelope)`, `UNIQUE(source, grantee)`) and cover the
  **whole subtree below them**: children inherit access through the
  share that covers their ancestor, resolved by walking the parent
  chain (64-hop cap) - one row, not a copy.
- A share appears in the grantee's root file tree under a unique
  display name (`Projekte` becomes `Projekte (alice) 2` on collision).
  Everything a grantee creates inside a shared folder lands in the
  *owner's* tree and counts against the *owner's* quota.
- The same resolution runs for the REST API and for WebDAV: an
  inactive account can still be a grantee, the share simply becomes
  visible once the account is activated.
- Revoking (`DELETE /api/shares/:id`, owner or grantee) takes effect
  immediately; `GET /api/shares/outgoing` and `/incoming` list both
  directions.

## 4. Encrypted content: the key envelope

For accounts with encryption on, the share carries one extra piece: a
**key envelope** sealed client-side to the grantee's public key before
the request goes. The server stores it opaque (present-and-<= 8192
chars is all it checks) and hands it back on `/api/shares/incoming`;
that blob plus the grantee's own private key is what makes a shared
encrypted folder readable. The dialog shows the grantee's key
fingerprint for out-of-band comparison before you trust the exchange
(TOFU), and `PERM_UPDATE` gates every write to a key record, mirroring
the API permission. Design: ENCRYPTION.md 5.5.

## 5. Boundaries

- Moves and copies refuse to cross owners and enforce the bits
  inherited from any covering share.
- The SHARE bit is reserved: re-sharing to a third account is not
  wired up yet, so a grantee cannot widen a grant.
- Group folders are **not** shareable to individuals - membership is
  what grants access there ([groups.md](groups.md)); anonymous access
  goes through public links instead ([public_links.md](public_links.md)).

## 6. Where it lives

- Code: `src/sharing.rs` (the bitmask and its helpers),
  `src/db/share.rs` (rows, covering shares, mount names),
  `src/web/routes/shares.rs`.
- API: [API.md](../API.md) - Permissions section (mask table, mount
  naming, move/copy rules).
- Encryption: [ENCRYPTION.md](../ENCRYPTION.md) 5.5 (sharing as key
  exchange).
- User side: [USERGUIDE.md](../USERGUIDE.md) section 5.
- Tests: `tests/suite.sh` sections "share batch", "share dialog: user
  dropdown", plus the permission pins in the accounts section.
