# fxcloud

A Nextcloud-inspired personal cloud, written in Rust, that compiles down to a
**single binary**. Start it, open your browser, and you get a familiar
login + file-explorer experience — no external database, no separate frontend
build step, no runtime dependencies.

## Features (current milestone)

- **Single binary** – SQLite (bundled) + frontend assets are embedded inside the
  executable. Just run it.
- **User accounts** – registration & login with Argon2id password hashing.
  Accounts start **inactive** and are switched on/off with a single column in
  the database until a user-administration UI exists — see
  [Account activation](#account-activation).
- **Sessions** – HttpOnly cookie sessions, stored server-side, with expiry and
  background cleanup.
- **File explorer** – a Nextcloud-style web UI to:
  - browse a folder tree with breadcrumbs
  - create folders
  - upload files **or whole folders** (buttons, or drag & drop into the
    dropzone — folder trees are recreated including empty subfolders)
  - download, copy/move (destination picker), rename, and delete entries
    via a per-row ⋮ menu (folders delete recursively)
  - **multi-select** rows (checkbox per row, header checkbox = all,
    Shift+click = a range) and process them together: delete, move/copy,
    share, or download the whole selection as **one ZIP** (folders keep
    their structure)
- **Sharing** – share files/folders with other users using a Nextcloud-style
  permission bitmask; shares mount directly in the grantee's root tree and are
  enforced everywhere (web UI and WebDAV). See [Sharing](#sharing).
- **WebDAV** – mount your files with real sync clients (Nextcloud desktop,
  rclone, Cyberduck, Windows "Map network drive", etc.). See
  [WebDAV](#webdav) below.
- **Clean, modular architecture** – see below.

## Quick start

```bash
# build
cargo build --release

# run (creates ./data with the DB and blobs)
./target/release/fxcloud
```

Then open <http://127.0.0.1:8080>, create an account, and start uploading.

> The **very first** account you register is activated automatically — it is
> your own login on a fresh instance. There is no separate admin concept yet,
> and every account registered after that starts inactive: see
> [Account activation](#account-activation).

## Account activation

Each user row carries an `is_active` flag (`0`/`1`). An inactive account can be
registered, but it can neither sign in (web) nor authenticate (WebDAV), and
deactivating a user cuts access off **immediately** — including sessions and
WebDAV mounts that are already open, because the flag is checked on every
request.

There is no user-administration UI yet, so the switch is flipped directly in
the database (no restart required). The path below is the development layout
(`./data`); on a systemd deployment the file is `/home/fxcloud/data/fxcloud.db`:

```bash
DB=data/fxcloud.db                      # systemd: /home/fxcloud/data/fxcloud.db

# overview
sqlite3 "$DB" "SELECT id, username, is_active, created_at FROM users ORDER BY id;"

# activate -> the owner can sign in from now on
sqlite3 "$DB" "UPDATE users SET is_active = 1 WHERE username = 'max';"

# deactivate -> session cookie and WebDAV credentials stop working right away
sqlite3 "$DB" "UPDATE users SET is_active = 0 WHERE username = 'max';"
```

What users see:

- **Login with an inactive account** (correct password) → `403` with
  *"account is not activated yet – ask an administrator to activate it"*.
  Wrong passwords still get a plain `401`.
- **Registering** an inactive account → `202` with
  `{"pending_activation": true}` and *no* session cookie; the login page
  reports "Account created. It has to be activated before you can sign in."
  (The first account on a fresh instance instead signs in right away.)
- **WebDAV** with an inactive account → `403` instead of a `401` password
  prompt loop.

Sharing still works both ways for inactive accounts — shares simply become
visible to the grantee once their account is activated.

## Prebuilt binaries

Every tagged release on [GitHub Releases](https://github.com/floyd54/fxcloud/releases)
ships a prebuilt binary:

- `fxcloud-<tag>-x86_64-unknown-linux-musl` – a **fully static** Linux x86_64
  build (~5 MB) with no runtime dependencies: download, `chmod +x fxcloud`,
  run.

Why only one build? There is exactly **one development environment** behind
this project – my Linux x86_64 machine – and I don't maintain a zoo of build
environments for other platforms. On macOS, ARM64, Windows, … just build from
source (see [Quick start](#quick-start)); it's a plain
`cargo build --release` with no extra tooling.

New tags get their binary attached automatically by GitHub Actions
(`.github/workflows/release.yml`).

## Configuration

Everything is configurable via environment variables:

| Variable                | Default         | Description                          |
| ----------------------- | --------------- | ------------------------------------ |
| `FXCLOUD_BIND`          | `127.0.0.1`     | Address to bind the HTTP server      |
| `FXCLOUD_PORT`          | `8080`          | TCP port                             |
| `FXCLOUD_DATA`          | `./data`        | Data directory (DB + file blobs)     |
| `FXCLOUD_SESSION_TTL`   | `2592000`       | Session lifetime in seconds (30 days)|
| `FXCLOUD_SECURE_COOKIE` | `false`         | Set `Secure` on cookies (enable behind HTTPS) |
| `FXCLOUD_MAX_UPLOAD_MB` | `1024`          | Max request body for uploads, in MiB (fixes large-file multipart uploads) |
| `RUST_LOG`              | `fxcloud=info`  | Log filter (tracing)                 |

Example:

```bash
FXCLOUD_BIND=0.0.0.0 FXCLOUD_PORT=9000 FXCLOUD_DATA=/srv/fxcloud ./fxcloud
```

## Deployment

### Behind a reverse proxy (HTTPS)

fxcloud speaks plain HTTP and has no built-in upload limit, so your reverse
proxy must handle TLS **and** allow large uploads:

- Raise the body-size limit (e.g. nginx `client_max_body_size 10G;`), otherwise
  uploads over the proxy default (1 MB) fail. Keep it in sync with the app-side
  limit `FXCLOUD_MAX_UPLOAD_MB` (default 1024) — a file must be under **both**.
- Forward `Host`, `X-Real-IP`, `X-Forwarded-For`, and `X-Forwarded-Proto`.
- Set `FXCLOUD_SECURE_COOKIE=1` so session cookies get the `Secure` attribute.

Example nginx location:

```nginx
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header Host              $host;
    proxy_set_header X-Real-IP         $remote_addr;
    proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
    proxy_request_buffering off;
    proxy_buffering off;
}
```

### systemd

The service runs as an unprivileged system user `fxcloud` (group `fxcloud`,
shell `nologin`) — never as root. Its home directory holds both the binary
and the data partition:

```
/home/fxcloud/fxcloud    # executable (ExecStart)
/home/fxcloud/data/      # FXCLOUD_DATA: SQLite DB + file blobs
```

A hardened unit file is provided in [`deploy/fxcloud.service`](deploy/fxcloud.service)
(`NoNewPrivileges`, `ProtectSystem=strict`, `ReadWritePaths` limited to the
data directory, …).

```bash
# 1. Create the user and install the binary
sudo useradd --system --user-group --create-home --home-dir /home/fxcloud \
     --shell /usr/sbin/nologin fxcloud
sudo install -m755 target/release/fxcloud /home/fxcloud/fxcloud
sudo mkdir -p /home/fxcloud/data      # or move an existing ./data here
sudo chown -R fxcloud:fxcloud /home/fxcloud
sudo chmod 750 /home/fxcloud

# 2. Install & start the service
sudo cp deploy/fxcloud.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fxcloud

# 3. Check status / logs (journald, no log files on disk)
sudo systemctl status fxcloud
sudo journalctl -u fxcloud -f

# 4. Later: roll out a new build
sudo systemctl stop fxcloud
sudo install -m755 target/release/fxcloud /home/fxcloud/fxcloud
sudo systemctl start fxcloud
```

The repo checkout itself is *not* used at runtime — the source tree can stay
wherever development happens (e.g. `/root/fxcloud`).

## Architecture

```
src/
├── main.rs          # bootstrap: config, db, background tasks, server
├── config.rs        # env-driven configuration
├── error.rs         # unified AppError (maps to HTTP responses)
├── models.rs        # shared data types (User, FileEntry, DTOs)
├── auth/            # password hashing, session cookie, AuthUser extractor
├── db/              # pooled SQLite access + migrations
│   ├── mod.rs       # Db wrapper (async via spawn_blocking)
│   ├── user.rs      # user records
│   ├── session.rs   # session records + token generation
│   └── file.rs      # file-tree metadata (recursive ops, breadcrumbs)
├── files/           # FileService: DB metadata + on-disk blob storage
└── web/             # axum routing layer
    ├── mod.rs       # router assembly
    ├── state.rs     # shared AppState
    ├── ui.rs        # serves the embedded frontend + auth-gated pages
    └── routes/
        ├── auth.rs  # /api/register, /login, /logout, /me
        └── files.rs # /api/files/*
frontend/            # static UI, embedded via rust-embed
migrations/          # SQL schema (idempotent or guarded, applied at startup)
```

### Design notes

- **Storage**: each file's content is stored at
  `<data>/blobs/<owner-id>/<year>/<h1>/<h2>/<file-id>` — the owner's tree and
  the creation year first (convenient for per-user and per-year backups), then
  two id levels (`h1` covers 65 536 ids, `h2` covers 256), so no directory
  ever holds more than 256 blobs. The leaf name is the plain database row id:
  unique by construction and immune to path-traversal, and the path stays
  recomputable from a row without extra state. Blobs from installations that
  predate this layout are moved into place automatically at startup (idempotent,
  logged); reads and deletes fall back to the old flat `<data>/blobs/<file-id>`
  path, so nothing goes missing even if a move fails. Rollback note: builds
  older than this do not know the structure — roll back from a backup or move
  the blobs flat again first.
- **Blocking SQLite**: rusqlite is synchronous, so every DB call is transparently
  routed through `tokio::task::spawn_blocking` inside the `Db` wrapper. Handlers
  simply `await`.
- **Auth**: the `AuthUser` axum extractor resolves the session cookie into a
  logged-in user, returning `401` otherwise — handlers just accept `AuthUser`.

## HTTP API

All `/api/*` routes require a session cookie (except `register` / `login`).

| Method | Path                    | Body / Query                       | Description                 |
| ------ | ----------------------- | ---------------------------------- | --------------------------- |
| POST   | `/api/register`         | `{username, password, display_name?}` | Create account (202 `pending_activation` while inactive; the first account signs in) |
| POST   | `/api/login`            | `{username, password}`             | Sign in (`403` when the account is inactive) |
| POST   | `/api/logout`           | –                                  | Sign out                    |
| GET    | `/api/me`               | –                                  | Current user                |
| GET    | `/api/files`            | `?parent=<id>` (omit for root)     | List folder contents        |
| GET    | `/api/files/breadcrumb` | `?id=<folderId>`                   | Breadcrumb trail            |
| POST   | `/api/files/folder`     | `{parent_id, name}`                | Create folder               |
| POST   | `/api/files/folder/ensure` | `{parent_id, name}`             | Get-or-create folder (idempotent; powers folder uploads) |
| POST   | `/api/files/upload`     | multipart: `parent`, `file`        | Upload file                 |
| GET    | `/api/files/download`   | `?id=<fileId>`                     | Download file               |
| GET    | `/api/files/info`       | `?id=<entryId>`                    | One entry + viewer rights   |
| POST   | `/api/files/rename`     | `{id, name}`                       | Rename entry                |
| POST   | `/api/files/delete`     | `{id}`                             | Delete (recursive for dirs) |
| POST   | `/api/files/move`       | `{id, dest_parent}`                | Move entry (keeps name)     |
| POST   | `/api/files/copy`       | `{id, dest_parent}`                | Copy entry/subtree + blobs  |
| POST   | `/api/files/batch/delete` | `{ids}`                         | Delete a selection (per-item outcome) |
| POST   | `/api/files/batch/move` | `{ids, dest_parent}`               | Move a selection            |
| POST   | `/api/files/batch/copy` | `{ids, dest_parent}`               | Copy a selection            |
| POST   | `/api/files/zip`        | `{ids}`                            | Prepare a ZIP download → `{token}` |
| GET    | `/api/files/zip`        | `?token=<token>`                   | Stream the prepared ZIP (single use, 5 min) |
| POST   | `/api/shares`           | `{file_id, username, permissions?}`| Share with a user           |
| POST   | `/api/shares/batch`     | `{file_ids, username, permissions?}` | Share a selection with one user |
| DELETE | `/api/shares/:id`       | –                                  | Revoke share (owner/grantee)|
| GET    | `/api/shares/outgoing`  | `?file_id=<id>` (optional filter)  | Shares I created            |
| GET    | `/api/shares/incoming`  | –                                  | Shares given to me          |

`dest_parent: null` targets your own root. Moves keep the original name
(collisions return `409`), refuse crossing owners, and enforce the permission
bitmask (`2` update, `4` create, `8` delete) inherited from any covering share.

The `batch/*` endpoints answer with `{ok: [ids], failed: [{id, name, error}]}`.
Items are processed **independently** on purpose: an entry the caller may not
touch (or whose name already exists at the destination) is reported in
`failed`, while the rest of the selection still goes through — nothing is
rolled back. The single-item `delete` / `move` / `copy` / `shares` routes stay
for API compatibility and take a one-element list in the UI.

ZIP downloads are split into two steps so the URL stays short regardless of how
many ids are selected (proxies cap request lines around 8 KB): the `POST`
hands out a single-use token valid for five minutes, the `GET` builds the
archive on a background thread and streams it. The archive is assembled in
memory, so one download is capped at **1 GiB uncompressed** — the error tells
you to take fewer items. Folders are packed with their structure and the
modification times of the entries; content that disappeared in the meantime is
skipped and listed in `fxcloud-skipped.txt` inside the archive.

## Sharing

Sharing uses a Nextcloud-style permission bitmask:

| Bit | Value | Meaning                                            |
| --- | ----- | -------------------------------------------------- |
| READ | 1 | View/download, list folder contents           |
| UPDATE | 2 | Overwrite file content, rename/move            |
| CREATE | 4 | Add files/folders inside a shared folder       |
| DELETE | 8 | Delete the item (or children of a folder)      |
| SHARE | 16 | Reserved for re-sharing (not wired up yet)     |

A share appears directly in the grantee's **root file tree** under a unique
display name (`Projekte` → `Projekte (alice) 2` on collision) and resolution
crosses into the owner's subtree from there. Everything a grantee creates inside
a shared folder lands in the *owner's* tree. Authorization always asks "do I own
this, or does a covering share grant the required bit?" — so children of a
shared folder inherit the folder's share. The same rules apply to the web UI and
to WebDAV (`/dav/`).

## WebDAV

fxcloud exposes a WebDAV endpoint at **`/dav/`**, authenticated with **HTTP
Basic auth** (your fxcloud username + password). The path after `/dav/` is
relative to your home folder.

```bash
# quick check
curl -u USER:PASS -X PROPFIND -H "Depth: 1" https://your-host/dav/

# with rclone
rclone config   # type: webdav, url: https://your-host/dav/, user/pass
rclone lsd remote:

# Windows "Map network drive" / macOS Finder "Connect to Server" -> /dav/
```

Supported methods: `OPTIONS`, `PROPFIND` (Depth 0 / 1 / infinity), `GET`,
`HEAD`, `PUT`, `DELETE`, `MKCOL`, `MOVE`, `COPY`, `LOCK`, `UNLOCK`.

Notes:
- `LOCK`/`UNLOCK` are **permissive no-ops** (a token is issued but not tracked),
  just enough to keep Office/Windows clients happy.
- Uploads go through your reverse proxy — remember to raise
  `client_max_body_size` (see [Deployment](#deployment)).

## Roadmap ideas

- File sharing between users, permissions, groups
- Versioning & trashbin
- Calendar / Contacts (CalDAV / CardDAV)
- In-browser file preview (images, text, PDF)
- TLS termination & `Secure` cookies

## License

MIT
