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
| PUT    | `/api/me/password`      | `{current_password, new_password}` | Change the signed-in user's password (401 when the current one is wrong, 400 when the new one is shorter than 8 characters); the calling session stays open, every other session of the account ends |
| POST   | `/api/passkeys/register/start` | `{}`                   | Begin adding a device: WebAuthn creation options bound to this session, `excludeCredentials` from the account's existing passkeys; `400` when the request's `Origin` disagrees with the deployment origin |
| POST   | `/api/passkeys/register/finish` | `{label?, credential}` | Verify the attestation and store the device -> `201` with the row (`label`: trimmed, 1-100 chars, default `Passkey`; `409` when the authenticator is already registered; `401` unknown, replayed or foreign ceremony) |
| POST   | `/api/passkeys/login/start` | `{username}`              | **Public.** Sign-in challenge; byte-for-byte identical answer for unknown names and accounts without passkeys (one random dummy `allowCredentials` entry - no account oracle) |
| POST   | `/api/passkeys/login/finish` | `{credential}`            | **Public.** Verify the assertion -> session cookie + user. `401` unknown/replayed/wrong credential, `400` origin/rpId/counter, `403` inactive (only after the credential checked out) |
| GET    | `/api/me/passkeys`      | -                                  | The signed-in account's devices: `id`, `label`, `created_at`, `last_used_at`, `transports` |
| PATCH  | `/api/me/passkeys/:id`  | `{label}`                          | Rename one device (`400` blank or longer than 100 chars, `404` unknown or foreign id) |
| DELETE | `/api/me/passkeys/:id`  | -                                  | Remove one device (`404` unknown or foreign id); removing the last one is allowed - the password keeps working |
| GET    | `/api/me/sessions`      | -                                  | The account's live sessions: `sid` (public handle, never the token), `created_at`, `last_seen_at`, `expires_at`, `user_agent`, `current` for the calling cookie |
| DELETE | `/api/me/sessions`      | -                                  | End every session but the calling one -> `{ended: n}` (the incident button; the caller stays signed in) |
| DELETE | `/api/me/sessions/:sid` | -                                  | End one of your own sessions by handle (`404` unknown or foreign sid - never a hint that it exists) |
| GET    | `/api/users`            | -                                  | Accounts to share with (everyone but you: `username`, `display_name`, `is_active`) |
| GET    | `/api/admin/users`      | -                                  | **Admin only (403 otherwise).** Every account for the administration table: `id`, `username`, `display_name`, `is_active`, `is_admin`, `quota_bytes`, `used_bytes`, `created_at` |
| PUT    | `/api/admin/users/:id`  | `{is_active?}`, `{is_admin?}`, `{quota_bytes?}` | **Admin only.** Partial update of one account; only the fields present are written. Refuses self-deactivation (400), deactivating/demoting the last active admin (400) and a negative quota (400); returns the updated row |
| POST   | `/api/admin/users/:id/password` | -                        | **Admin only.** Reset the account's password; returns `{username, temporary_password}` with a one-time generated password (16 chars) for the next sign-in |
| GET    | `/api/files`            | `?parent=<id>` (omit for root)     | List folder contents (dir rows carry `subtree_bytes`) |
| GET    | `/api/files/breadcrumb` | `?id=<folderId>`                   | Breadcrumb trail (starts with an id-less `Home` crumb; every keyed level carries its `enc_key`) |
| POST   | `/api/files/folder`     | `{parent_id, name}` (+ `group` at the root) | Create folder. With `group: <id>` and `parent_id: null` it bootstraps that group's top-level folder instead (member with CREATE; `group` next to a real `parent_id` = 400; see Group folders) |
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
| GET    | `/api/files/versions`  | `?id=<fileId>`                     | Version history of a file, newest first (READ; a share grantee sees it too) |
| GET    | `/api/files/version/download` | `?id=<fileId>&vid=<versionId>` | Stream one kept version (206/416 ranges like `/download`; type from the version's `enc_version`) |
| POST   | `/api/files/version/restore` | `?id=<fileId>&vid=<versionId>` | Exchange restore: the version becomes the content, the outgoing content becomes the newest version (UPDATE) |
| DELETE | `/api/files/version`   | `?id=<fileId>&vid=<versionId>`     | Drop one version and its bytes (UPDATE) |
| POST   | `/api/shares`           | `{file_id, username, permissions?, envelope?}` | Share with a user (`envelope` = opaque key envelope sealed to the grantee, ENCRYPTION.md 5.5; empty or > 8192 chars = 400) |
| POST   | `/api/shares/batch`     | `{items: [{file_id, envelope?}], username, permissions?}` | Share a selection with one user (one envelope per item; the old `file_ids` body no longer deserializes) |
| DELETE | `/api/shares/:id`       | -                                  | Revoke share (owner/grantee)|
| GET    | `/api/shares/outgoing`  | `?file_id=<id>` (optional filter)  | Shares I created            |
| GET    | `/api/shares/incoming`  | -                                  | Shares given to me          |
| GET    | `/api/groups`           | -                                  | The caller's groups: raw array `[{id, name, role, quota_bytes, used_bytes}]` (`role` 1 = manager, 0 = member; empty for a non-member - the one listing not wrapped in `entries`) |
| GET    | `/api/groups/keys`      | -                                  | Key envelopes sealed to me: `[{file_id, group_id, group_name, envelope, created_at}]` (empty for a member who has not been handed a key yet) |
| GET    | `/api/groups/:id/keys/pending` | -                          | **Manager only (403 for a member, 404 for a non-member).** One pair per member without an envelope - including the manager's own: `[{file_id, folder_name, user_id, username, display_name, has_public_key}]` |
| POST   | `/api/groups/:id/keys`  | `{file_id, user_id, envelope}`     | **Manager only.** Seal one top-level folder's key record to one member -> `{ok: true}`; upsert on `(file_id, user_id)` (re-distribution overwrites); empty or > 8192-char `envelope` = 400; the folder must belong to this group and the recipient to its membership |
| GET    | `/api/admin/groups`     | -                                  | **Admin only (403 otherwise).** Every group: `[{id, name, quota_bytes, used_bytes, created_by, created_by_name, created_at, members: [{user_id, username, display_name, role, added_at}]}]` |
| POST   | `/api/admin/groups`     | `{name, quota_bytes}`              | **Admin only.** Create a group -> the group row; the creator becomes its first manager (409 on a duplicate name, case-insensitive; empty name = 400) |
| PUT    | `/api/admin/groups/:id` | `{name?}`, `{quota_bytes?}`        | **Admin only.** Partial update, each present field written on its own; lowering the quota below current usage is allowed (growth stops, files stay) |
| DELETE | `/api/admin/groups/:id` | -                                  | **Admin only.** Delete a group -> `{ok: true}`; refused with 409 while any member or any attributed row remains (trashed rows count - empty the group first) |
| POST   | `/api/admin/groups/:id/members` | `{username, role}`          | **Admin only.** Add a member (role 0/1 only, else 400) -> the new member list; unknown account or group = 404, already a member = 409 |
| PUT    | `/api/admin/groups/:id/members/:uid` | `{role}`                | **Admin only.** Change one member's role -> the member list (role 0/1 only, else 400) |
| DELETE | `/api/admin/groups/:id/members/:uid` | -                     | **Admin only.** Remove a member -> the member list; their key envelopes for this group go with them |

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

Sessions last **7 days** by default (`FXCLOUD_SESSION_TTL`, seconds)
and slide while in use: any API request carrying the cookie rewrites
the expiry to now + TTL, at most once per renewal window (a quarter of
the lifetime, capped at a day), so an active session never dies under
its user and the hot path costs one indexed no-op statement. The
listing shows `sid` because a session's primary key IS the secret
token - an endpoint handing out tokens would defeat the HttpOnly
cookie - and a sid is a label, not a key: every operation through it is
scoped to the caller, so another account's sid is `404`. Renewal does
not rotate the token value (a second tab would bounce to the login
page mid-renewal); the countermeasure for a leaked cookie is the
listing itself, which names the device it was created on. WebDAV is
exempt - it authenticates with Basic per request and holds no session.

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

## Group folders

A group is a storage principal of its own (concepts/groups.md): its rows
carry `owner_group_id`, its writes bill the group's `quota_bytes`, and
every member works the same tree through the role mask `role` derives
(manager = full, member = everything but the group-management gates).
`owner_id` stays the creator either way - attribution is the audit trail,
never the access decision - and the root listing wears the group's name
as a badge, so a personal folder of the same name stays tellable apart.

- **Bootstrap.** `POST /api/files/folder {"parent_id": null, "group":
  <id>, "name": ...}` creates the group's top-level folder (member with
  CREATE; a `group` next to a real `parent_id` = 400). Below that root
  every member works the subtree normally - upload, rename, move, trash -
  and one name per parent is unique across *all* members (one partial
  index), not per creator.
- **No sharing out.** `POST /api/shares` on a group row answers 403:
  v1 keeps shares strictly user-to-user; group targets arrive with G2.
- **Quota.** The group's usage is live sizes plus version rows, trash
  included (a trashed row bills until the purge), checked on every write
  like a user's quota (507 when full). Members never spend their own
  budget on group writes, and lowering a quota below current usage is
  allowed: files stay, growth stops.
- **Trash.** Any member sees the group's trashed rows in *their* trash
  view and may restore or purge them - the DELETE bit comes from the role
  mask, not from creator attribution.
- **Key distribution.** Folder keys travel manager -> member through the
  pending list and `POST /api/groups/:id/keys`. The envelope is the
  share's shape (ENCRYPTION.md 5.5, same AAD derivation, same 8192-char
  cap), so a member's tab opens it through the same key map as a mount;
  the server stores it opaque. Removing a member deletes their envelopes
  for that group with them. Inside a group the record-swap line holds:
  the first key record on a row may be set by any member with UPDATE,
  swapping an existing one is manager-only (403).
- **Delete.** A group disappears only when it is empty - no members, no
  rows attributed to it, trashed rows counting. The admin empties it
  first; the refusal is a 409, never a silent cascade.

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
