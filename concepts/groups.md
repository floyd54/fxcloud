# Concept: groups and group folders (decided)

Status: decided 2026-10-30. Implementation order: **3 of 3** - after
streaming S1 and versioning. Green means the open questions are answered
(section 11); this document is the working spec until the feature ships.

## 1. Goal

Folders that **belong to a group**, not to a member: a shared workspace
with its own quota, managed membership and roles. "Gruppenordner" - the
user's original request - answered as first-class storage principals,
not as shares routed through a group.

## 2. What it builds on (current state)

- Shares are strictly user-to-user: `shares(source_id, owner_id,
  grantee_id, permissions, envelope)` with `UNIQUE(source, grantee)`;
  `covering_share` walks the parent chain (64-hop cap); the grantee
  root lists rows `WHERE grantee_id = me`.
- Permission bits: READ/UPDATE/CREATE/DELETE/SHARE (`src/sharing.rs`).
- E2EE sharing: one ECIES envelope per share row (ENCRYPTION.md 5.5),
  TOFU fingerprints, key-blind server.
- Admin surface exists (`is_admin`, user table, `/api/admin/*` behind
  `AdminUser`), single-pane dialog today.
- Quota: per user; `used_bytes = SUM(live sizes)`.
- Blob paths shard by `owner_id` - user id 5 and group id 5 must not
  collide (namespace, section 3).

## 3. Data model (migration `015_groups.sql`)

```sql
CREATE TABLE groups (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    name       TEXT NOT NULL UNIQUE COLLATE NOCASE,
    quota_bytes INTEGER NOT NULL,          -- operator-set
    created_by INTEGER REFERENCES users(id),
    created_at TEXT NOT NULL
);
CREATE TABLE group_members (
    group_id INTEGER NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role     INTEGER NOT NULL,             -- 0 = member, 1 = manager
    added_at TEXT NOT NULL,
    UNIQUE(group_id, user_id)
);
-- E2EE: one envelope per (top-level group folder, member); children
-- follow the parent-wraps-child hierarchy as everywhere else.
CREATE TABLE group_keys (
    file_id  INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    user_id  INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    envelope TEXT NOT NULL,                -- base64 ECIES, <= 8192 chars
    created_at TEXT NOT NULL,
    UNIQUE(file_id, user_id)
);
ALTER TABLE files ADD COLUMN owner_group_id INTEGER
    REFERENCES groups(id) ON DELETE RESTRICT;   -- NULL = personal
```

- `owner_id` keeps the **creator** (audit: who made the row);
  `owner_group_id` carries **attribution** (whose storage, whose
  quota), materialized on every row of the subtree at create/move-in
  time - no parent walking at quota time.
- Blob namespace: personal rows keep their exact paths forever (no
  migration); group rows get a distinct namespace (`BlobRef` gains an
  owner kind) so group 5 can never shadow user 5.
- Group deletion is refused while the group owns live files (`RESTRICT`
  + explicit check with a clear 409).

## 4. Permission model v1

- **One role per membership, applying to all group folders:** manager =
  `PERM_ALL`, member = READ|UPDATE|CREATE|DELETE (SHARE unused - see
  boundary below). Per-folder ACLs are a later add-on.
- Effective mask = membership role for the file's `owner_group_id`.
  Root listing joins group folders in with a group badge (the share
  surfacing pattern, one more column).
- **Boundaries v1 (documented, not accidental):**
  - No re-sharing *out of* a group folder to individuals
    (`shares.owner_id` is a user; a group is not) - 403 with a clear
    message.
  - Copy/move *into* a group folder works (attribution set from the
    parent at write time); move *out* clears attribution and re-checks
    quotas.
  - Group files take no incoming shares (403 on share creation with a
    group-owned source).
- **Trash:** group rows trashed by a member appear in the trash view of
  every member (list/restore queries gain `owner_group_id IN (my
  groups)`); restore rights = DELETE bit; the age-based system sweep
  purges them like everything else.
- **Quota:** every write path (upload, editor save, WebDAV PUT,
  move/copy-in) checks the attributed group's `quota_bytes`;
  `used = SUM(live sizes WHERE owner_group_id = G)`. Shown read-only to
  members, editable in the admin dialog.

## 5. E2EE (in v1, as decided)

- Plaintext group folders work from day one (DECISION 2 of
  ENCRYPTION.md allows mixed mode).
- Encrypted group folders anchor their key hierarchy at the **top-level
  group folder key** (there is no user root above it): children wrap to
  parents as everywhere, and each member receives one envelope
  `ECIES(member_public_key, top_folder_key)` in `group_keys` - the same
  primitive and the same server blindness as share envelopes.
- **Distribution is a manager action** (the key-blind server cannot
  mint envelopes): the folder UI lists "N members still need the key"
  and one click wraps for the missing set (fetch
  `GET /api/keys/<user>`, reuse the batch envelope shape). TOFU
  fingerprints apply per member, as with shares.
- Member leaves: their envelope row goes away; **no retroactive
  re-key** - identical to share revocation, and folder re-key remains
  ENCRYPTION.md phase 6 / DECISION 4. Stated openly in the UI help.
- Key-record swaps (`PUT /api/files/key`) on group rows: **managers
  only** (owner-equivalent); members may pass their own record back
  unchanged, never swap - the F5 rule carries over with "owner" read as
  "manager".

## 6. Admin and UX

- Admin dialog gains a **Groups** section: create/rename/delete (empty
  only), set quota, add/remove members from the active-user list, role
  select. Only `is_admin` manages groups (decision 5).
- File UI: group folders in the root with a badge; manager may rename /
  delete the top-level folder; members work the subtree normally.
- Share dialog unchanged in v1 (group targets arrive with G2).
- i18n keys in all three languages (en, de, tlh).

## 7. Phase G2 (later, same tables)

"Share your own folder to a group": materialized member shares with
`shares.grantee_group_id` for management, member rows created only for
members without a direct share (**direct share wins**, UI hint), revoke
removes only group-created rows, E2EE envelopes completed per member
via the same pending-key list. Kept out of v1 to keep the first release
one coherent idea.

## 8. Security

- The server stays the permission authority; nothing new is trusted to
  the client.
- Group membership is **not a secrecy boundary against the operator**
  (the operator sees members and can read plaintext folders - the same
  statement shares make today; documented in the UI help).
- Admin-only group management, every route behind `AdminUser`; member
  mutations (trash/restore/roles) go through the normal file permission
  checks plus the role mask.
- Quota is operator-set: a group cannot grow past its budget.

## 9. Test strategy

Unit: attribution at create/move-in/out, role masks, quota boundary,
manager-vs-member key-swap rule. Suite: create group + folder; member
sees the root entry; member bits enforced (member can write, cannot
re-share out -> 403); manager renames; small group quota set via sqlite
blocks the next upload; member removal -> entry gone (404); trash view +
restore of a group file by a member; E2EE path (envelope distribution,
pending list, member without envelope sees name only); admin routes 403
for non-admins; i18n keys x3; count bump in the three docs.

## 10. Size: **L** (migration, admin section, file-UI surfacing, role +
quota enforcement across write paths, trash queries, E2EE
distribution flow, ~14 pins)

## 11. Decisions (summary)

| # | Question | Decision |
| --- | --- | --- |
| 5 | Who manages groups | **admin only** (user-owned groups later if ever) |
| 6 | Direct vs group grant conflict | direct share wins (relevant from G2 on) |
| 7 | E2EE distribution | manager click / pending-key list (key-blind server), **in v1** |
| 8 | Quota | **own quota per group**, operator-set, enforced on every write |
| - | Shape | group-owned folders (storage principals), not share routing; roles manager/member; no re-share out of group folders in v1; trash visible to members; delete group only when empty; order 3 of 3 |
