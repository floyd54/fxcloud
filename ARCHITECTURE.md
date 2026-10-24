# fxcloud architecture

fxcloud is a single Rust binary (axum + rusqlite): the SQLite database and
the whole web frontend are embedded into the executable via `rust-embed`.
There is no external database, no separate frontend build and no runtime
dependency beyond libc.

## Code layout

```
src/
|-- main.rs          # bootstrap: config, migrations, background tasks, server
|-- config.rs        # env-driven configuration (bind, port, data dir, TTLs)
|-- error.rs         # unified AppError -> HTTP status + JSON message
|-- models.rs        # shared data types (User, FileEntry, request/response DTOs)
|-- auth/            # Argon2id hashing, session cookie, AuthUser extractor
|-- db/              # SQLite access + migrations
|   |-- mod.rs       # Db wrapper: every call via spawn_blocking
|   |-- user.rs      # user records (quota_bytes, is_active)
|   |-- session.rs   # session rows + token generation
|   |-- file.rs      # file-tree metadata: recursive ops, breadcrumbs,
|   |                #   subtree sizes, quota gates
|   \-- share.rs     # share records: covering shares, mount names
|-- sharing.rs       # permission bitmask (PERM_*) and helpers
|-- files/           # FileService: DB metadata + on-disk blob storage
|-- webdav.rs        # WebDAV protocol layer mounted at /dav/
\-- web/             # axum routing layer
    |-- mod.rs       # router assembly
    |-- state.rs     # shared AppState (db, config)
    |-- ui.rs        # embedded pages + version slot injection
    \-- routes/
        |-- auth.rs  # /api/register, /login, /logout, /me, /users
        |-- files.rs # /api/files/* (listing, upload, preview, editor, zip)
        \-- shares.rs# /api/shares/*
frontend/            # static UI (plain JS, no framework), embedded at build time
migrations/          # SQL schema, idempotent, applied at startup
deploy/              # hardened systemd unit
```

## Request flow

A request hits an axum route; handlers take the session cookie through the
`AuthUser` extractor (missing/invalid session -> `401`, inactive account ->
treated as logged out). Database work goes through the `Db` wrapper, which
runs rusqlite calls on the blocking pool (`spawn_blocking`) - handlers just
`await`. File content is served/stored by `FileService`, which owns the
mapping between a database row and its blob on disk.

## Storage design

Each file's content lives at

```
<data>/blobs/<owner-id>/<year>/<h1>/<h2>/<file-id>
```

Owner and creation year first (convenient for per-user and per-year
backups), then two id levels (`h1` covers 65 536 ids, `h2` covers 256), so
no directory ever holds more than 256 blobs. The leaf name is the plain
database row id: unique by construction, immune to path-traversal, and the
path is recomputable from a row without extra state. Installations that
predate this layout are migrated at startup (idempotent, logged); reads and
deletes fall back to the old flat `<data>/blobs/<file-id>` path.

## Permission model

Authorization always asks "does the caller own this entry, or does a
covering share grant the required bit?" (`src/db/file.rs`,
`src/sharing.rs`). Shares are per-entry and cover the whole subtree below
them, so children inherit access through the share that covers their
ancestor. The same resolution runs for the REST API and for WebDAV, so a
grantee sees and may change exactly the same things in both.

## Quotas

Each account carries a `quota_bytes` column (default 1 GiB). What counts is
the summed `size` of the entries the account *owns*; content shared to
someone else is served from the owner's quota. Enforcement sits in the
database layer next to the write itself: creating a file, overwriting one
(only the growth counts) and copying a subtree (checked up front for the
whole tree, so a full quota never leaves a partial copy behind). Exceeding
the quota yields `507 Insufficient Storage` with a readable message - the
web UI and WebDAV both surface it.

## Folder sizes

Directory rows in listings carry `subtree_bytes`, the recursive sum of
everything inside the folder. It is computed by a single recursive CTE over
the `parent_id` index per listing page (`fill_subtree_sizes` in
`src/db/file.rs`), not one query per row and not a cached counter that
every write would have to maintain.

## Sessions & activation

Sessions are server-side rows behind an HttpOnly cookie with a TTL
(default 30 days) and a background cleanup task. Every request checks the
account's `is_active` flag, so deactivating a user cuts off web sessions
and WebDAV access immediately without a restart.

## Frontend & preview safety

The frontend is plain HTML/JS/CSS embedded at compile time and served with
`Cache-Control: no-cache` (assets are not fingerprinted yet). The version
badge next to the logo is filled server-side from `Cargo.toml` at build
time, so the displayed number always matches the binary.

Preview responses are always `nosniff` with `CSP: sandbox`, so rendered
HTML/SVG cannot touch the session cookie of the app origin. Content types
come from an extension allowlist; byte ranges are supported so media
seeking works. The built-in Markdown preview escapes everything up front
and filters link targets, so a note cannot run script.
