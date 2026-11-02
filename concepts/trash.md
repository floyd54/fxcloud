# Concept: the trash

Status: **implemented** (baseline feature; the retention sweep, the
per-entry purge deadline and empty-trash followed later).

## 1. Goal

Nothing disappears on the first click. Deletion is a *mark*, not a
removal: a restore is a single UPDATE, and a background sweep - not a
user gesture - is what finally frees the bytes.

## 2. How it works

- `trash_entry` sets `deleted_at` on the entry only, so its subtree
  rows and blobs stay exactly where they are. Only **trashed roots**
  (parent live or absent) are units; `under_trash` walks the parent
  chain to keep everything below a trashed folder invisible to reads,
  writes and WebDAV.
- The trash listing shows one row per restore unit with `deleted_at`
  and the computed `purge_at` deadline. **Restore** clears the mark; a
  name taken in the meantime gets a ` (restored)` suffix (or
  ` (restored N)`), so a restore always succeeds visibly. **Delete
  permanently** purges one row, **Empty trash** purges the caller's
  whole trash.
- A background sweep hard-deletes expired roots on the
  `FXCLOUD_TRASH_SWEEP_SECS` interval (default hourly): rows via the
  foreign-key cascade, blobs afterwards. Retention is
  `FXCLOUD_TRASH_DAYS` (default 30).
- Trashed entries are invisible to every other operation and **keep
  counting against the owner's quota** while they sit there
  ([quotas.md](quotas.md)). Upload rollbacks bypass the trash via
  `hard_delete_entry`, because those rows never existed for the user.

## 3. Boundaries

- Group rows trashed by a member appear in the trash view of *every*
  member; restore rights come from the DELETE bit of the role mask,
  not from creator attribution (see [groups.md](groups.md)).
- Public-link deletions land in the **owner's** trash, never in limbo
  ([public_links.md](public_links.md)).
- Version history survives in the trash: a file's kept versions stay
  until the file itself is purged ([versioning.md](versioning.md)).

## 4. Where it lives

- Code: `src/db/file.rs` (`trash_entry`, `under_trash`,
  `hard_delete_entry`), the sweep task in `src/main.rs`.
- Model: [ARCHITECTURE.md](../ARCHITECTURE.md) - trash bin.
- API: [API.md](../API.md) - Trash section (`/api/files/trash*`).
- User side: [USERGUIDE.md](../USERGUIDE.md) section 7.
- Tests: `tests/suite.sh` section "trash: delete -> restore ->
  retention purge".
