# fxcloud HTTP API

All `/api/*` routes require the session cookie set by `POST /api/login`
(HttpOnly). Missing or invalid session -> `401`; authenticated but not
allowed -> `403`. Only `register` and `login` are public.

## Endpoints

| Method | Path                    | Body / Query                       | Description                 |
| ------ | ----------------------- | ---------------------------------- | --------------------------- |
| POST   | `/api/register`         | `{username, password, display_name?}` | Create account (202 `pending_activation` while inactive; the first account signs in) |
| POST   | `/api/login`            | `{username, password}`             | Sign in (`403` when the account is inactive) |
| POST   | `/api/logout`           | -                                  | Sign out                    |
| GET    | `/api/me`               | -                                  | Current user + `quota_bytes` / `used_bytes` |
| GET    | `/api/users`            | -                                  | Accounts to share with (everyone but you: `username`, `display_name`, `is_active`) |
| GET    | `/api/files`            | `?parent=<id>` (omit for root)     | List folder contents (dir rows carry `subtree_bytes`) |
| GET    | `/api/files/breadcrumb` | `?id=<folderId>`                   | Breadcrumb trail            |
| POST   | `/api/files/folder`     | `{parent_id, name}`                | Create folder               |
| POST   | `/api/files/file`       | `{parent_id, name}`                | Create empty file (409 on duplicates) |
| POST   | `/api/files/folder/ensure` | `{parent_id, name}`             | Get-or-create folder (idempotent; powers folder uploads) |
| POST   | `/api/files/upload`     | multipart: `parent`, `file`        | Upload file                 |
| GET    | `/api/files/download`   | `?id=<fileId>`                     | Download file               |
| GET    | `/api/files/preview`    | `?id=<fileId>` (+ optional `Range`) | Inline preview (206/416 ranges; `CSP: sandbox` for HTML/SVG) |
| PUT    | `/api/files/content`    | `?id=<fileId>`, body = raw text    | Overwrite file content (editor save; quota-checked, 507 when full) |
| GET    | `/api/files/info`       | `?id=<entryId>`                    | One entry + viewer rights   |
| POST   | `/api/files/rename`     | `{id, name}`                       | Rename entry                |
| POST   | `/api/files/delete`     | `{id}`                             | Delete (recursive for dirs) |
| POST   | `/api/files/move`       | `{id, dest_parent}`                | Move entry (keeps name)     |
| POST   | `/api/files/copy`       | `{id, dest_parent}`                | Copy entry/subtree + blobs  |
| POST   | `/api/files/batch/delete` | `{ids}`                         | Delete a selection (per-item outcome) |
| POST   | `/api/files/batch/move` | `{ids, dest_parent}`               | Move a selection            |
| POST   | `/api/files/batch/copy` | `{ids, dest_parent}`               | Copy a selection            |
| POST   | `/api/files/zip`        | `{ids}`                            | Prepare a ZIP download -> `{token}` |
| GET    | `/api/files/zip`        | `?token=<token>`                   | Stream the prepared ZIP (single use, 5 min) |
| GET    | `/api/files/trash`      | -                                  | Trash: trashed roots with `deleted_at` / `purge_at` |
| POST   | `/api/files/trash/restore` | `{id}`                           | Bring a trashed entry back (suffix on name clash) |
| POST   | `/api/files/trash/purge` | `{id}`                            | Delete one trashed entry for good |
| POST   | `/api/files/trash/empty` | -                                 | Delete the caller's whole trash now |
| POST   | `/api/shares`           | `{file_id, username, permissions?}`| Share with a user           |
| POST   | `/api/shares/batch`     | `{file_ids, username, permissions?}` | Share a selection with one user |
| DELETE | `/api/shares/:id`       | -                                  | Revoke share (owner/grantee)|
| GET    | `/api/shares/outgoing`  | `?file_id=<id>` (optional filter)  | Shares I created            |
| GET    | `/api/shares/incoming`  | -                                  | Shares given to me          |

## Account activation

Every user row carries an `is_active` flag. Accounts after the first start
inactive; the flag is checked on every request, so deactivating a user cuts
access off immediately (open sessions and WebDAV mounts included). What the
API answers:

- **Login, inactive account** (correct password) -> `403` with
  *"account is not activated yet - ask an administrator to activate it"*.
  Wrong passwords get a plain `401`.
- **Register, while activation is pending** -> `202` with
  `{"pending_activation": true}` and no session cookie. The first account
  on a fresh instance instead signs in right away.
- **WebDAV, inactive account** -> `403` instead of a `401` password loop.

Sharing still works both ways for inactive accounts; shares become visible
to the grantee once their account is activated.

## Permissions

Shares use a Nextcloud-style bitmask (default: read + update + create +
delete):

| Bit  | Value | Meaning                                   |
| ---- | ----- | ----------------------------------------- |
| READ | 1     | View/download, list folder contents       |
| UPDATE | 2   | Overwrite file content, rename/move       |
| CREATE | 4   | Add files/folders inside a shared folder  |
| DELETE | 8   | Delete the item (or children of a folder) |
| SHARE | 16   | Reserved for re-sharing (not wired up yet)|

A share appears in the grantee's root file tree under a unique display name
(`Projekte` -> `Projekte (alice) 2` on collision). Everything a grantee
creates inside a shared folder lands in the *owner's* tree. Children inherit
access through the covering share, and the same rules apply to the REST API
and to WebDAV.

Moves and copies take `dest_parent: null` for your own root, keep the
original name (`409` on collision), refuse crossing owners, and enforce the
permission bits above inherited from any covering share.

## Batch operations

The `batch/*` endpoints answer with `{ok: [ids], failed: [{id, name,
error}]}`. Items are processed **independently** on purpose: an entry the
caller may not touch (or whose name already exists at the destination) is
reported in `failed`, while the rest of the selection still goes through -
nothing is rolled back. The single-item `delete` / `move` / `copy` routes
stay for API compatibility and take a one-element list in the UI.

## Trash

Deletions never remove data directly: `files/delete` and `batch/delete`
(plus WebDAV `DELETE` and a MOVE/COPY overwrite) mark the entry with
`deleted_at` instead. Only the trashed root row is marked - its subtree and
blob content stay untouched, so a restore is a single UPDATE. The trash
listing shows one row per restore unit with `deleted_at` and the computed
`purge_at` deadline; `restore` clears the mark (a name taken in the
meantime gets a " (restored)" suffix). A background sweep hard-deletes
trash roots older than the retention window (`FXCLOUD_TRASH_DAYS`, default
30 days): rows via the foreign-key cascade, blobs afterwards. Trashed
entries are invisible to every other operation (listing, read, write,
WebDAV) and keep counting against the owner's quota while they sit in the
trash.

## ZIP downloads

ZIP downloads are split into two steps so the URL stays short regardless of
how many ids are selected (proxies cap request lines around 8 KB): the
`POST` hands out a single-use token valid for five minutes, the `GET` builds
the archive on a background thread and streams it. The archive is assembled
in memory, so one download is capped at **1 GiB uncompressed** - the error
tells you to take fewer items. Folders are packed with their structure and
the modification times of the entries; content that disappeared in the
meantime is skipped and listed in `fxcloud-skipped.txt` inside the archive.

## WebDAV

fxcloud exposes WebDAV at **`/dav/`**, authenticated with **HTTP Basic**
(fxcloud username + password). The path after `/dav/` is relative to your
home folder.

Supported methods: `OPTIONS`, `PROPFIND` (Depth 0 / 1 / infinity), `GET`,
`HEAD`, `PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`, `LOCK`, `UNLOCK`.

- `LOCK`/`UNLOCK` are **permissive no-ops** (a token is issued but not
  tracked), just enough to keep Office/Windows clients happy.
- WebDAV shares the quota, permission and activation paths with the web UI:
  a full quota yields `507`, a deactivated account `403`.
- Uploads go through your reverse proxy - its body-size limit must allow
  your file sizes (see the deployment section of the README).

Example:

```bash
curl -u USER:PASS -X PROPFIND -H "Depth: 1" https://your-host/dav/
```
