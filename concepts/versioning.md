# Concept: file versioning (decided)

Status: decided 2026-10-30, implemented the same day (v0.1.2).
Implementation order: **2 of 3** - after streaming S1 (same code paths),
before group folders. Green means the open questions are answered
(section 12); section 13 records where the shipped implementation
refines this spec.

## 1. Goal and non-goals

Goal: every content replacement keeps the replaced bytes as a restorable
previous version. The user can list the history of a file, download any
version, restore it, delete it - and restoring is itself undoable.

Non-goals: WebDAV versioning (RFC 5842), diff/merge, folder histories
(folders have no content), copy carrying history along, per-version
labels/comments (later if ever).

## 2. What it builds on (current state)

- One `files` row + one blob; replacements overwrite in place, paired by
  the per-row `begin_replace` mutex (DB statement + blob write).
- Four content-replacement paths: multipart upload, editor save
  (`PUT /api/files/content`), WebDAV `PUT`, copy/move-onto-existing.
- Trash: `deleted_at` soft-delete on the root row; the purge job
  cascades rows and deletes blobs separately (`delete_blobs`).
- Quota: `SUM(size)` over live rows (`db/user.rs`), reported as
  `used_bytes`.
- E2EE: DECISION 5 of ENCRYPTION.md - a save never rotates the key.
  One file key lives across all content versions of that entry. This is
  the lucky foundation: versions need no key records of their own.

## 3. Data model (migration `014_file_versions.sql`)

```sql
CREATE TABLE file_versions (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    file_id         INTEGER NOT NULL REFERENCES files(id) ON DELETE CASCADE,
    size            INTEGER NOT NULL,
    enc_version     INTEGER NOT NULL DEFAULT 0,
    author_id       INTEGER,             -- who saved this version
    blob_created_at TEXT NOT NULL,       -- part of the blob path (BlobRef)
    created_at      TEXT NOT NULL        -- when it was replaced FROM
);
CREATE INDEX idx_versions_file ON file_versions(file_id, created_at);

ALTER TABLE users ADD COLUMN version_keep_n    INTEGER NOT NULL DEFAULT 20;
ALTER TABLE users ADD COLUMN version_keep_days INTEGER NOT NULL DEFAULT 180;
```

- Version blobs live in their own path space (`_versions/<file_id>/...`),
  a `BlobRef` variant carries `blob_created_at`; `blob_path`/`delete_blobs`
  are already generic over refs.
- Quota becomes `SUM(files) + SUM(file_versions)` over the user's rows.
- The purge path deletes version rows by cascade and must collect the
  version blobs as well (same enumeration pass as today's blobs).

## 4. The replace flow (crash-safe, memory-free)

All replacements happen under the existing `begin_replace` lock:

1. New bytes arrive streamingly into a temp file (streaming S1 - the
   reason this ships second).
2. `fs::hardlink(entry_path -> version_path)` - the outgoing bytes get a
   second name for the price of a directory entry, **no content copy**.
3. Insert the `file_versions` row (link before row: a crash leaves an
   orphan file, never a row pointing at nothing).
4. `rename(temp -> entry_path)` - atomic; the entry keeps the old inode
   alive under its version name.

Same filesystem is guaranteed (temp lives under `data_dir/tmp`), so both
operations are metadata-only and constant-memory even for GiB files.

**Restore = an exchange, not a copy.** The chosen version becomes
current, the outgoing current becomes a new version:

1. `hardlink(entry_path -> new_version_path)` + insert its row (the
   outgoing content stays reachable under both names).
2. `hardlink(chosen_version_path -> temp)` then
   `rename(temp -> entry_path)`.
3. Delete the chosen version's row and unlink its path (the entry now
   holds that inode).
4. Update `size`, `modified_at`; run retention.

Crash at any point leaves orphans (cleaned like `_orphans`) or a briefly
duplicated readable row - never an unreadable entry. Restore does not
change the byte total: everything is hardlinks; quota counts entries
(logical accounting, documented).

## 5. Retention (decided: both bounds, per user, in Settings)

- Two per-user values, editable in the settings dialog (Account pane,
  new section next to Storage): **keep last N versions per file**
  (default 20) and **max age in days** (default 180). `0` disables the
  respective bound; both may be `0`.
- N is enforced immediately after every insert (per file).
- Age is enforced by the existing sweep loop (same cadence as the trash
  sweep): delete versions older than the author's cutoff.
- Group folders arrive later (concept `groups.md`); until they do,
  retention applies to personal files. The forward-compatible rule for
  then: the group has no user prefs - use a fixed group policy or the
  acting manager's prefs (open, revisit with groups).

## 6. API

| Endpoint | Rule |
| --- | --- |
| `GET /api/files/versions?id=` | list metadata (READ) |
| `GET /api/files/version/download?id=&vid=` | stream one version (READ) |
| `POST /api/files/version/restore` | exchange restore (UPDATE) |
| `DELETE /api/files/version?id=` | drop one version (UPDATE) |

Permission checks reuse `entry_for_read` / the UPDATE grant exactly like
today's mutations.

## 7. UI

Context menu / info: "Version history" dialog - rows with time, size,
current marker; actions download / restore / delete, restore confirms.
i18n keys in all three languages (en, de, tlh). The storage widget
already shows `used_bytes`, which now includes history - no new surface.

## 8. Security

- READ lists and downloads, UPDATE restores and deletes - no new
  permission types, no route outside the session gate.
- Deleting a version deletes the bytes (row + blob): delete means
  delete.
- Retention bounds growth, quota includes history: no silent disk DoS.
- E2EE unchanged: the file key never rotates (DECISION 5), so a grantee
  who holds the envelope can read history - which decision 2 of section
  12 makes explicit rather than accidental.

## 9. WebDAV

Stays version-blind: PROPFIND/GET/PUT act on the current content only.
PUT participates in the replace flow (its history is kept like any
other save).

## 10. Test strategy

Unit: retention boundaries (N, days, 0=off), the exchange sequence in a
tempdir (crash-order properties), quota sum including versions. Suite
pins: double upload lists two versions; restore swaps and shows the
previous current as newest version; READ grantee downloads a version;
trash keeps history and purge removes version rows *and* blobs
(filesystem check, like existing blob pins); retention prunes at N;
settings fields persist per user; i18n keys x3; count bump in the three
docs.

## 11. Size: **M** (migration, 4 routes, BlobRef variant, quota+purge,
retention sweep, settings section, one dialog, ~10 pins)

## 12. Decisions (summary)

| # | Question | Decision |
| --- | --- | --- |
| 1 | Retention | **both bounds** - keep N AND max age, per user, configurable in the Settings dialog, defaults 20 / 180 days, 0 = off |
| 2 | Who sees history | owner **and READ grantees** (they hold the key anyway) |
| 3 | Which events count | **every content replacement**: upload, editor save, WebDAV PUT, move-onto-existing |
| 4 | Quota | history **counts** toward `used_bytes` |
| 5 | Copy | copies carry the current content only; move/rename carry history (same row) |
| 6 | WebDAV | invisible (no RFC 5842) |
| 7 | Order | after streaming S1, before groups |

## 13. Implementation notes (what shipped differs, and why)

Refinements recorded while building it (v0.1.2), so the spec above stays
readable as the intent:

- **Which paths version today.** The multipart upload is create-only
  (`409` on a duplicate name), so no upload overwrites anything: the
  replacement paths that keep history are the editor save and the WebDAV
  `PUT`. Copy/move-onto-existing trash the old entry instead of replacing
  it in place, and its history follows the row into the trash (decision
  5), so there is nothing to pin there either. The pin hook lives in the
  one shared replace step (`pin_content_as_version`), so a future
  overwrite-capable upload joins by calling it.
- **Version key.** `blob_created_at` is not a timestamp: it is the whole
  path component, `<microseconds>-<16 hex random>` - unique by
  construction, which the link-before-row crash rule needs (a lookup
  cannot exist yet, and two saves under one lock are microseconds apart).
  The path is `_versions/<file_id>/<key>` with no year levels.
- **Quota gate order.** The metadata statement (UPDATE grant + quota)
  runs *before* the pin. With a pin the quota delta is the incoming
  `size` alone: the outgoing bytes stay in the total, moving from the
  files sum to the versions sum.
- **Zero-byte outgoing is never versioned.** The first fill of an empty
  file keeps no empty history; `pin_content_as_version` returns without
  a row.
- **Restore touches `enc_version` too.** The exchange updates `size`,
  `enc_version` and `modified_at` - the version's bytes are ciphertext
  iff they were ciphertext when saved. `enc_key` stays untouched
  (DECISION 5: one file key across all versions).
- **Grant before bytes.** A restore asserts the UPDATE grant
  (`require_update`) before its first hardlink, not only in the later
  metadata statement: the exchange starts by naming bytes.
- **Orphans.** Like `_orphans`, there is no automatic GC: a crash between
  link and row leaves one orphan file under `_versions/`, harmless and
  rare.
- **Version download is ranged.** Beyond the spec's "stream one version"
  it shares the download helper, so ranges (206/416) work on versions.
- **UI current marker.** The dialog lists only kept versions; the
  current content is the file itself in the listing behind it, so no
  "current" row is rendered.
- **Delete route** takes `?id=&vid=` (the spec's table forgot the
  version id).
