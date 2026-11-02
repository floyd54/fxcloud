# Concept: the file explorer

Status: **implemented** (baseline feature; batch endpoints, ZIP
downloads and the hidden-files toggle followed later, the blob layout
migrated in the flat-blobs sweep).

## 1. Goal

A familiar file manager in the browser: folders with breadcrumbs and
recursive sizes, create and upload (files *or* whole folder trees),
rename, move/copy, delete, multi-select with bulk actions - and the
same rules enforced over WebDAV, so a desktop client sees exactly what
the web UI allows.

## 2. Listing and navigation

- `GET /api/files?parent=<id>` (no parameter = your root) returns the
  folder's children; directory rows carry `subtree_bytes`, the
  recursive sum of everything inside them, computed by one recursive
  CTE over the `parent_id` index per listing page - not one query per
  row and not a cached counter every write would have to maintain
  (`fill_subtree_sizes` in `src/db/file.rs`).
- `GET /api/files/breadcrumb?id=<folderId>` walks back up; the trail
  starts with an id-less `Home` crumb.
- **Show hidden** toggles entries whose name starts with a dot; the
  choice is remembered in the browser. The listing has its own sort
  order (name/size/time, directories first).

## 3. Creating and uploading

- `POST /api/files/folder` and `POST /api/files/file` create entries
  in the current folder (`409` on duplicates). A new text file opens
  straight in the built-in editor.
- `POST /api/files/folder/ensure` is the idempotent get-or-create that
  powers folder uploads: a dropped folder tree - empty subfolders
  included - arrives as one ensure per level plus one upload per file.
- `POST /api/files/upload` (multipart: `parent`, `file`) streams the
  body through the temp pipeline of `concepts/streaming.md`: counted
  against `max_upload_bytes` while writing (413 past it), committed by
  an atomic rename, MIME decided from the *bytes* (magic numbers first,
  then a text heuristic over a bounded prefix sample) rather than from
  the browser's `Content-Type`.
- Uploads, editor saves, WebDAV `PUT`s and move/copy-in all check the
  quota of the tree's owner next to the write itself.

## 4. Rearranging

- `POST /api/files/rename`, `/move`, `/copy` take an entry id; a move
  or copy takes `dest_parent` (`null` = your own root), keeps the
  original name (`409` on collision), refuses to cross owners and
  enforces the permission bits inherited from any covering share.
- The `batch/*` siblings (`delete`, `move`, `copy`) take a list and
  answer `{ok: [ids], failed: [{id, name, error}]}`. Items are
  processed **independently** on purpose: an entry the caller may not
  touch is reported in `failed` while the rest still goes through -
  nothing is rolled back.
- Delete is a trash mark, never a removal - see
  [trash.md](trash.md).

## 5. ZIP downloads

Two steps, so the URL stays short regardless of how many ids are
selected (proxies cap request lines around 8 KB): `POST /api/files/zip`
hands out a single-use token valid for five minutes, `GET ...?token=`
builds the archive on a background thread and streams it. The archive
is capped at **1 GiB uncompressed** (the error tells you to take fewer
items); folders keep their structure and the modification times of the
entries, content that disappeared in the meantime is skipped and
listed in `fxcloud-skipped.txt` inside the archive.

## 6. Where it lives

- Code: `src/files/` (FileService: DB metadata + on-disk blobs),
  `src/db/file.rs` (recursive ops, sizes, quota gates),
  `src/web/routes/files.rs`.
- Storage layout: [ARCHITECTURE.md](../ARCHITECTURE.md) - storage
  design (the `<owner>/<year>/<h1>/<h2>/<id>` blob path).
- Memory profile and byte ranges: [streaming.md](streaming.md).
- API: [API.md](../API.md) - endpoint table, batch operations, ZIP
  downloads.
- User side: [USERGUIDE.md](../USERGUIDE.md) section 4.
- Tests: `tests/suite.sh` sections "blob layout", "batch move",
  "batch copy", "ZIP as alice", "folder sizes in the listing",
  "file list sorting", "hidden files toggle".
