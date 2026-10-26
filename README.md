# fxcloud

A Nextcloud-inspired personal cloud, written in Rust, that compiles to a
**single binary**: SQLite and the web frontend are embedded, there is no
external database and no runtime dependency. Start it, open
<http://127.0.0.1:8080>, register - and you get a familiar file explorer
with sharing, quotas and WebDAV.

## Features

- **Single binary** - bundled SQLite + embedded frontend; just run it.
- **Accounts & sessions** - registration/login (Argon2id), HttpOnly cookie
  sessions. The first account on a fresh instance becomes your login;
  later accounts are activated with one SQL statement (see
  [Managing users & quotas](#managing-users--quotas)).
- **User settings** - the name in the top bar opens a menu: account facts
  (username, member since, storage used), a display name you can change
  yourself, a light/dark theme and a password change that asks for the
  current password first. Everything is stored per account on the server,
  so it follows you to every device.
- **File explorer** - folders with breadcrumbs and recursive sizes,
  create/upload (files *or* whole folder trees via drag & drop, empty
  subfolders included), rename, move/copy, delete, multi-select with
  download of the whole selection as one ZIP.
- **Preview & editor** - images, video, audio, PDF, HTML and text open in
  a lightbox inside the app (HTML/SVG are sandboxed server-side, byte
  ranges make media seeking work). Text files open in a built-in editor
  with live Markdown preview; new text files are created directly in the
  UI. Encrypted files open the same way: the tab decrypts them into a
  Blob URL, so images, video, audio, PDF and HTML preview with encryption
  on, and an encrypted text file edits just like a plaintext one.
- **Sharing** - share files/folders with other accounts using a permission
  bitmask (read 1, update 2, create 4, delete 8); shares mount in the
  grantee's root tree and are enforced in the web UI *and* WebDAV. When
  encryption is on, the share also carries a key envelope sealed to the
  grantee's public key - their fingerprint is shown for out-of-band
  comparison - so they can unlock and actually open what is inside.
  Details: [API.md](API.md#permissions).
- **WebDAV** - mount your files with Nextcloud desktop clients, rclone,
  Cyberduck, Windows network drives (see [WebDAV](#webdav)).
- **Quotas** - 1 GiB per account by default, enforced with
  `507 Insufficient Storage`, usage shown in the topbar.
- **Trash** - deletions go to a per-user trash first; restore entries with
  one click, and everything older than 30 days is purged for good by a
  background sweep.

## Install

### Prebuilt binary

Every tagged release on [GitHub
Releases](https://github.com/floyd54/fxcloud/releases) ships a fully
static Linux x86_64 build (~6 MB, no runtime dependencies):

```bash
chmod +x fxcloud-<tag>-x86_64-unknown-linux-musl
FXCLOUD_DATA=/srv/fxcloud ./fxcloud-<tag>-x86_64-unknown-linux-musl
```

Other platforms (macOS, ARM64, Windows, ...) build from source with a plain
`cargo build --release` - no extra tooling. Why only one prebuilt target?
There is exactly one development machine behind this project; new tags get
their binary attached automatically by GitHub Actions
(`.github/workflows/release.yml`).

### From source

```bash
cargo build --release
./target/release/fxcloud      # creates ./data with the DB and file blobs
```

Open <http://127.0.0.1:8080> and register: the **first account** on a fresh
instance is activated automatically, every later account starts inactive.

## Configuration

Everything is configured via environment variables:

| Variable                | Default         | Description                          |
| ----------------------- | --------------- | ------------------------------------ |
| `FXCLOUD_BIND`          | `127.0.0.1`     | Address to bind the HTTP server      |
| `FXCLOUD_PORT`          | `8080`          | TCP port                             |
| `FXCLOUD_DATA`          | `./data`        | Data directory (DB + file blobs)     |
| `FXCLOUD_SESSION_TTL`   | `2592000`       | Session lifetime in seconds (30 days)|
| `FXCLOUD_SECURE_COOKIE` | `false`         | Set `Secure` on cookies (enable behind HTTPS) |
| `FXCLOUD_MAX_UPLOAD_MB` | `1024`          | Max request body for uploads, in MiB |
| `FXCLOUD_TRASH_DAYS`    | `30`            | Days a trashed entry is kept before the purge removes it |
| `FXCLOUD_TRASH_SWEEP_SECS` | `3600`       | Interval of the trash purge sweep, in seconds |
| `RUST_LOG`              | `fxcloud=info`  | Log filter (tracing)                 |

```bash
FXCLOUD_BIND=0.0.0.0 FXCLOUD_PORT=9000 FXCLOUD_DATA=/srv/fxcloud ./fxcloud
```

## Deployment

### systemd

The provided hardened unit
([`deploy/fxcloud.service`](deploy/fxcloud.service)) runs as an
unprivileged system user, never as root:

```bash
sudo useradd --system --user-group --create-home --home-dir /home/fxcloud \
     --shell /usr/sbin/nologin fxcloud
sudo install -m755 target/release/fxcloud /home/fxcloud/fxcloud
sudo mkdir -p /home/fxcloud/data      # or move an existing ./data here
sudo chown -R fxcloud:fxcloud /home/fxcloud

sudo cp deploy/fxcloud.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now fxcloud

sudo systemctl status fxcloud         # logs: sudo journalctl -u fxcloud -f
```

Rolling out a new build: `sudo systemctl stop fxcloud`, replace the binary,
`sudo systemctl start fxcloud`.

### Behind a reverse proxy (HTTPS)

fxcloud speaks plain HTTP, so the proxy must terminate TLS - and allow
large uploads:

- Raise the body-size limit (nginx: `client_max_body_size 10G;`) and keep
  it in sync with `FXCLOUD_MAX_UPLOAD_MB` - a file must be under both.
- Forward `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`.
- Set `FXCLOUD_SECURE_COOKIE=1` so cookies get the `Secure` attribute.

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

## Managing users & quotas

There is no user-administration UI yet; both switches live in the database
(no restart required). On a systemd deployment the file is
`/home/fxcloud/data/fxcloud.db`, in development `./data/fxcloud.db`:
*Display name, theme and password are not on this list: every user changes
those themselves in the app, via the menu behind their name in the top bar.*

```bash
DB=/home/fxcloud/data/fxcloud.db

# overview
sqlite3 "$DB" "SELECT id, username, is_active, quota_bytes FROM users ORDER BY id;"

# activate / deactivate (takes effect instantly: sessions + WebDAV included)
sqlite3 "$DB" "UPDATE users SET is_active = 1 WHERE username = 'max';"
sqlite3 "$DB" "UPDATE users SET is_active = 0 WHERE username = 'max';"

# quota (bytes; 1073741824 = 1 GiB, the default for every account)
sqlite3 "$DB" "UPDATE users SET quota_bytes = 2147483648 WHERE username = 'alice';"
```

Inactive accounts can neither sign in nor authenticate over WebDAV and get
`403` with a hint to contact the administrator. What exactly counts against
a quota and how it is enforced: [ARCHITECTURE.md](ARCHITECTURE.md#quotas).

## WebDAV

fxcloud speaks WebDAV at **`/dav/`** with HTTP Basic auth (your fxcloud
username + password); the path after `/dav/` is relative to your home
folder:

```bash
rclone config    # type: webdav, url: https://your-host/dav/, user/pass
rclone lsd remote:

# Windows "Map network drive" / macOS Finder "Connect to Server" -> /dav/
```

Supported methods and protocol notes: [API.md](API.md#webdav).

## Testing

Two layers, both runnable straight after a checkout:

```bash
cargo test          # unit tests: permissions, quota, KDF floor, filename and
                    # RFC 5987 encoding, session-cookie parsing
./tests/suite.sh    # integration: 315 checks against a throwaway instance
```

`tests/suite.sh` starts its own fxcloud on a loopback port with a temporary
data directory, drives it over HTTP, WebDAV and the encryption endpoints, and
tears it down again - including on an early exit. It runs `cargo build` first,
because it asserts that the served version badge matches `Cargo.toml`, and a
stale binary would otherwise be a red check rather than a quiet pass. It needs
`curl`, `perl`, `sqlite3` and `node`; the JavaScript syntax checks use `qjsc`
when it is installed and `node --check` otherwise. It never reads your own
configuration or data.

CI runs both layers on every push and pull request
(`.github/workflows/test.yml`).

## More documentation

- [ENCRYPTION.md](ENCRYPTION.md) - client-side per-file encryption: threat
  model, cryptographic design, the DECISIONs behind it, and the phases
- [ARCHITECTURE.md](ARCHITECTURE.md) - code layout, storage format,
  permission and quota model
- [API.md](API.md) - HTTP endpoints, batch/ZIP semantics, WebDAV details

## License

MIT
