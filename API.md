# fxcloud HTTP API

All `/api/*` routes require the session cookie set by `POST /api/login`
(HttpOnly). Missing or invalid session -> `401`; authenticated but not
allowed -> `403`. Only `register`, `login` and the two `passkeys/login/*`
ceremony endpoints are public.

## Endpoints

| Method | Path                    | Body / Query                       | Description                 |
| ------ | ----------------------- | ---------------------------------- | --------------------------- |
| POST   | `/api/register`         | `{username, password, display_name?}` | Create account (202 `pending_activation` while inactive; the first account signs in) |
| POST   | `/api/login`            | `{username, password}`             | Sign in (`403` when the account is inactive) |
| POST   | `/api/logout`           | -                                  | Sign out                    |
| GET    | `/api/me`               | -                                  | Current user + `quota_bytes` / `used_bytes` / `theme` |
| PUT    | `/api/me`               | `{display_name?}` and/or `{theme}` | Save the settings from the user menu; theme must be `light` or `dark`, display name non-empty (max 100 chars); returns the updated user (400 when the body changes nothing) |
| PUT    | `/api/me/password`      | `{current_password, new_password}` | Change the signed-in user's password (401 when the current one is wrong, 400 when the new one is shorter than 8 characters); the session stays open |
| POST   | `/api/passkeys/register/start` | `{}`                   | Begin adding a device: WebAuthn creation options bound to this session, `excludeCredentials` from the account's existing passkeys; `400` when the request's `Origin` disagrees with the deployment origin |
| POST   | `/api/passkeys/register/finish` | `{label?, credential}` | Verify the attestation and store the device -> `201` with the row (`label`: trimmed, 1-100 chars, default `Passkey`; `409` when the authenticator is already registered; `401` unknown, replayed or foreign ceremony) |
| POST   | `/api/passkeys/login/start` | `{username}`              | **Public.** Sign-in challenge; byte-for-byte identical answer for unknown names and accounts without passkeys (one random dummy `allowCredentials` entry - no account oracle) |
| POST   | `/api/passkeys/login/finish` | `{credential}`            | **Public.** Verify the assertion -> session cookie + user. `401` unknown/replayed/wrong credential, `400` origin/rpId/counter, `403` inactive (only after the credential checked out) |
| GET    | `/api/me/passkeys`      | -                                  | The signed-in account's devices: `id`, `label`, `created_at`, `last_used_at`, `transports` |
| PATCH  | `/api/me/passkeys/:id`  | `{label}`                          | Rename one device (`400` blank or longer than 100 chars, `404` unknown or foreign id) |
| DELETE | `/api/me/passkeys/:id`  | -                                  | Remove one device (`404` unknown or foreign id); removing the last one is allowed - the password keeps working |
| GET    | `/api/users`            | -                                  | Accounts to share with (everyone but you: `username`, `display_name`, `is_active`) |
| GET    | `/api/admin/users`      | -                                  | **Admin only (403 otherwise).** Every account for the administration table: `id`, `username`, `display_name`, `is_active`, `is_admin`, `quota_bytes`, `used_bytes`, `created_at` |
| PUT    | `/api/admin/users/:id`  | `{is_active?}`, `{is_admin?}`, `{quota_bytes?}` | **Admin only.** Partial update of one account; only the fields present are written. Refuses self-deactivation (400), deactivating/demoting the last active admin (400) and a negative quota (400); returns the updated row |
| POST   | `/api/admin/users/:id/password` | -                        | **Admin only.** Reset the account's password; returns `{username, temporary_password}` with a one-time generated password (16 chars) for the next sign-in |
| GET    | `/api/files`            | `?parent=<id>` (omit for root)     | List folder contents (dir rows carry `subtree_bytes`) |
| GET    | `/api/files/breadcrumb` | `?id=<folderId>`                   | Breadcrumb trail (starts with an id-less `Home` crumb; every keyed level carries its `enc_key`) |
| POST   | `/api/files/folder`     | `{parent_id, name}`                | Create folder               |
| POST   | `/api/files/file`       | `{parent_id, name}`                | Create empty file (409 on duplicates) |
| POST   | `/api/files/folder/ensure` | `{parent_id, name}`             | Get-or-create folder (idempotent; powers folder uploads) |
| POST   | `/api/files/upload`     | multipart: `parent`, `file`        | Upload file. For plaintext uploads the stored `mime` is decided from the bytes (magic numbers first, then a text heuristic), not from the browser's `Content-Type`, which is `application/octet-stream` for a file without an extension; the declared type is only the fallback for binary the sniffer does not know, and encrypted uploads keep `mime` null |
| GET    | `/api/files/download`   | `?id=<fileId>`                     | Download file               |
| GET    | `/api/files/preview`    | `?id=<fileId>` (+ optional `Range`) | Inline preview (206/416 ranges; `CSP: sandbox` for HTML/SVG) |
| PUT    | `/api/files/content`    | `?id=<fileId>`, body = raw text    | Overwrite file content (editor save; quota-checked, 507 when full). Encrypted rows add `&enc=1&key=<base64 file key>` and require an `FXE1` body; a `key` requires `enc=1`, `enc=1` requires a key, and `enc=0` is refused on an encrypted row (ENCRYPTION.md 5.4) |
| PUT    | `/api/files/key`        | `{id, key}`                        | Store an entry's key record (a folder gaining its chain key, the re-bind a move or share performs). `key` is base64, PERM_UPDATE required, plaintext file = 400 (ENCRYPTION.md 5.4/5.5) |
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
| POST   | `/api/shares`           | `{file_id, username, permissions?, envelope?}` | Share with a user (`envelope` = opaque key envelope sealed to the grantee, ENCRYPTION.md 5.5; empty or > 8192 chars = 400) |
| POST   | `/api/shares/batch`     | `{items: [{file_id, envelope?}], username, permissions?}` | Share a selection with one user (one envelope per item; the old `file_ids` body no longer deserializes) |
| DELETE | `/api/shares/:id`       | -                                  | Revoke share (owner/grantee)|
| GET    | `/api/shares/outgoing`  | `?file_id=<id>` (optional filter)  | Shares I created            |
| GET    | `/api/shares/incoming`  | -                                  | Shares given to me          |

## Account activation

Every user row carries an `is_active` flag. Accounts after the first start
inactive; the flag is checked on every request, so deactivating a user cuts
access off immediately (open sessions and WebDAV mounts included). An
administrator flips the flag in the **User administration** dialog (or with
`PUT /api/admin/users/:id`). What the API answers:

- **Login, inactive account** (correct password) -> `403` with
  *"account is not activated yet - ask an administrator to activate it"*.
  Wrong passwords get a plain `401`.
- **Register, while activation is pending** -> `202` with
  `{"pending_activation": true}` and no session cookie. The first account
  on a fresh instance instead signs in right away.
- **WebDAV, inactive account** -> `403` instead of a `401` password loop.

Sharing still works both ways for inactive accounts; shares become visible
to the grantee once their account is activated.

## Passkeys

Passkeys (WebAuthn/FIDO2) are a second way in, not a second secret: the
account's password, its sessions, shares and the encryption hierarchy of
ENCRYPTION.md are untouched by them. The private half never leaves the
authenticator; the server stores the attested public key, the signature
counter and a label (migration `012_webauthn_credentials`).

Ceremony rules:

- **Username-first.** `login/start` takes the name and answers with an
  `allowCredentials` list; discoverable-credential-only flows are not part
  of the endpoints. Unknown name, account without passkeys and real account
  get byte-for-byte identical responses - the first two a single random,
  unusable entry instead of an empty list.
- **Challenges** are 32 random bytes held in memory for five minutes and
  single-use: redemption removes the entry (a replay -> `401`), and the
  ceremony kind is re-checked, so a registration challenge cannot open a
  session and a login challenge cannot register a device. A restart clears
  pending ceremonies; the user simply starts the dialog again.
- **Origin and rpId** come from `FXCLOUD_ORIGIN` when set, otherwise from
  `X-Forwarded-Proto` (or `FXCLOUD_SECURE_COOKIE`) plus `Host`. The browser
  sends `Origin` on the ceremony POSTs and it must equal that derived
  value - a mismatch is `400` with a pointer at `FXCLOUD_ORIGIN`, before a
  challenge is spent. Behind a reverse proxy the derived value is only
  right when the proxy forwards the scheme and `Host` unchanged; if it
  rewrites `Host`, terminates TLS without sending `X-Forwarded-Proto`, or
  users open the site under another host/port than the backend derives,
  set `FXCLOUD_ORIGIN` to the exact URL browsers see (scheme, host and
  port, no trailing slash). The rpId is the origin's host without port,
  and the rpId hash inside `authenticatorData` must match it (a
  credential minted for another domain -> `400`).
- **Algorithms:** ES256 on P-256 only (`pubKeyCredParams` offers `-7`, and
  the stored key must carry it). Attestation is requested as `none`;
  `packed` without a certificate chain is accepted (the fresh credential
  signs itself), a chain (`x5c`) is refused.
- **User verification is required** (`userVerification: "required"`, UP
  and UV flags checked): a PIN or biometric gesture, not just a touch.
- **Counter (clone detection):** a nonzero counter must strictly advance
  (`stored > 0 && new > 0 && new <= stored` -> `400`); authenticators that
  never count (many platform passkeys stay at 0) are exempt.
- **Account state is checked last**, exactly like the password flow: a
  valid passkey on a deactivated account gets `403`, and only after the
  credential itself verified.

Device management (`/api/me/passkeys`) renames and removes rows scoped to
the owner: a foreign or unknown id is `404`, never a hint that the id
exists somewhere else. Removing the last passkey is allowed on purpose -
the password keeps working, and cutting off a lost device must never be
blocked by a policy question.

Passkeys need a **secure context**: browsers expose
`navigator.credentials` only over HTTPS or on `localhost`. A passkey
sign-in carries no password, so there is nothing for the sign-in handoff
of ENCRYPTION.md 5.7 to park - the encryption pane asks for the storage
passphrase when it needs one, as it always did.

## Permissions

Shares use a Nextcloud-style bitmask (default: read + update + create +
delete):

| Bit  | Value | Meaning                                   |
| ---- | ----- | ----------------------------------------- |
| READ | 1     | View/download, list folder contents       |
| UPDATE | 2   | Overwrite file content, rename/move, store a key record (`PUT /api/files/key`) |
| CREATE | 4   | Add files/folders inside a shared folder  |
| DELETE | 8   | Delete the item (or children of a folder) |
| SHARE | 16   | Reserved for re-sharing (not wired up yet)|

A share appears in the grantee's root file tree under a unique display name
(`Projekte` -> `Projekte (alice) 2` on collision). Everything a grantee
creates inside a shared folder lands in the *owner's* tree. Children inherit
access through the covering share, and the same rules apply to the REST API
and to WebDAV.

For accounts with encryption on, the share carries one extra piece: the
**key envelope**, sealed client-side to the grantee's public key before the
request goes. The server stores it opaque, checks only that it is present
when given and at most 8192 characters, and hands it back on
`/api/shares/incoming` - that blob plus the grantee's own private key is
what makes a shared encrypted folder readable. See ENCRYPTION.md 5.5 for
the format, the AAD and the walk a grantee performs with it; PERM_UPDATE is
what gates every write to a key record, mirroring the API permission.

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
