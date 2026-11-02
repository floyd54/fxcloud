# fxcloud

A Nextcloud-inspired personal cloud, written in Rust, that compiles to a
**single binary**: SQLite and the web frontend are embedded, there is no
external database and no runtime dependency. Start it, open
<http://127.0.0.1:8080>, register - and you get a familiar file explorer
with sharing, quotas and version history. New to fxcloud? The
[User Guide](USERGUIDE.md) walks through the interface end to end.

## Features

- **Single binary** - bundled SQLite + embedded frontend, no database
  server, no runtime dependency ([INSTALL.md](INSTALL.md)).
- **Accounts & sessions** - registration/login (Argon2id), the first
  account becomes the administrator, later accounts are activated by an
  admin; every sign-in is its own session you can list and end, and
  display name, theme and password are self-service
  ([concepts/accounts.md](concepts/accounts.md)).
- **Passkeys (WebAuthn)** - sign in with a PIN or biometric instead of a
  password; devices are listed, renamed and removed in the user settings
  ([concepts/passkeys.md](concepts/passkeys.md)).
- **File explorer** - folders with breadcrumbs and recursive sizes,
  create/upload (files *or* whole folder trees via drag & drop), rename,
  move/copy, multi-select with the whole selection as one ZIP
  ([concepts/files.md](concepts/files.md)).
- **Preview & editor** - images, video, audio, PDF, HTML and text open in
  a lightbox (HTML/SVG sandboxed, byte ranges make media seeking work);
  text files edit in a built-in editor with live Markdown preview
  ([concepts/preview.md](concepts/preview.md)).
- **Version history** - every content replacement keeps a restorable
  version: download, restore, delete - restoring is itself undoable
  ([concepts/versioning.md](concepts/versioning.md)).
- **Sharing** - share files/folders with other accounts using a
  permission bitmask (read 1, update 2, create 4, delete 8), enforced in
  the web UI and WebDAV; encrypted content carries a key envelope sealed
  to the grantee ([concepts/sharing.md](concepts/sharing.md)).
- **Public links** - hand a folder or a single file to anyone with the
  URL: no account, three presets, rolling or fixed expiry, only the
  token's hash is stored ([concepts/public_links.md](concepts/public_links.md)).
- **Group folders** - a workspace that belongs to a *group* instead of
  one person: own quota, manager/member roles, one tree every member
  works directly ([concepts/groups.md](concepts/groups.md)).
- **Encryption** - files are encrypted in the browser before they leave
  it; the server stores ciphertext and a wrapped key
  ([ENCRYPTION.md](ENCRYPTION.md)).
- **Quotas** - 1 GiB per account by default, enforced with
  `507 Insufficient Storage`, usage shown in the topbar
  ([concepts/quotas.md](concepts/quotas.md)).
- **Trash** - deletions go to a per-user trash first; restore entries
  with one click, everything older than 30 days is purged by a
  background sweep ([concepts/trash.md](concepts/trash.md)).
- **Office documents** - open docx/xlsx/pptx/odt/ods/odp in the browser
  through an office engine (WOPI, e.g. Euro-Office or Collabora);
  optional, needs an engine sidecar, off unless configured
  ([concepts/office.md](concepts/office.md), setup in
  [INSTALL.md](INSTALL.md#office-integration-optional)).

## Install

```bash
curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | sh
```

That installs *and* updates fxcloud as a systemd service. Everything
else - prebuilt binary, build from source, the configuration table,
systemd, Docker and the reverse-proxy setup - lives in
[INSTALL.md](INSTALL.md).

## More documentation

- [USERGUIDE.md](USERGUIDE.md) - the user's guide: files, sharing,
  trash, quotas, encryption, passkeys, HTTPS/reverse proxy with
  `FXCLOUD_ORIGIN`, WebDAV, troubleshooting
- [INSTALL.md](INSTALL.md) - install and update, configuration,
  systemd, Docker, reverse proxy
- [ENCRYPTION.md](ENCRYPTION.md) - client-side per-file encryption:
  threat model, cryptographic design, the DECISIONs behind it, and the
  phases
- [ARCHITECTURE.md](ARCHITECTURE.md) - code layout, storage format,
  permission and quota model, tests
- [API.md](API.md) - HTTP endpoints, batch/ZIP semantics, WebDAV details
- [concepts/](concepts/) - one design note per feature: accounts,
  passkeys, files, preview, versioning, sharing, public links, groups,
  quotas, trash, [office documents](concepts/office.md) (WOPI with an
  optional engine sidecar) and [streaming](concepts/streaming.md), the
  memory profile every content path shares.
- [TRANSLATING.md](TRANSLATING.md) - adding a language to the UI

## License

MIT
