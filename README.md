# fxcloud

A Nextcloud-inspired personal cloud, written in Rust, that compiles to a
**single binary**: SQLite and the web frontend are embedded, there is no
external database and no runtime dependency. Start it, open
<http://127.0.0.1:8080>, register - and you get a familiar file explorer
with sharing, quotas and WebDAV. New to fxcloud? The
[User Guide](USERGUIDE.md) walks through the interface end to end.

## Features

- **Single binary** - bundled SQLite + embedded frontend; just run it.
- **Accounts & sessions** - registration/login (Argon2id), HttpOnly cookie
  sessions. The first account on a fresh instance becomes your login;
  later accounts are activated with one SQL statement (see
  [Managing users & quotas](#managing-users--quotas)).
- **Passkeys (WebAuthn)** - sign in with a PIN or biometric instead of a
  password (username-first FIDO2/WebAuthn, ES256, user verification
  required); devices are listed, renamed and removed in the user settings.
  Browsers only expose passkeys in a secure context, so this wants HTTPS
  (or localhost), and behind a reverse proxy that rewrites `Host` set
  `FXCLOUD_ORIGIN` to the URL users open the site under. Details:
  [API.md](API.md#passkeys).
- **User settings** - the name in the top bar opens a menu with a
  left-hand navigation and one pane at a time, so the dialog always
  fits the screen: **Account** (username, member since, storage used,
  and a display name you can change yourself), **Appearance** (a
  light/dark theme and a language that is remembered in this browser),
  **Password** (a change that asks for the current password first),
  **Sessions** (every sign-in is its own session with the device it was
  made on and when it was last used; end the ones you do not recognise
  on the spot, or end every other session at once with "sign out
  everywhere else") and **Passkeys**. Everything is stored per account
  on the server, so it follows you to every device.
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
  on, and an encrypted text file edits just like a plaintext one. The
  server reads the type of an uploaded file from its bytes (magic
  numbers, then a text heuristic), so a note without an extension still
  opens in the editor; the stored type also survives WebDAV writes and
  editor saves.
- **Sharing** - share files/folders with other accounts using a permission
  bitmask (read 1, update 2, create 4, delete 8); shares mount in the
  grantee's root tree and are enforced in the web UI *and* WebDAV. When
  encryption is on, the share also carries a key envelope sealed to the
  grantee's public key - their fingerprint is shown for out-of-band
  comparison - so they can unlock and actually open what is inside.
  Details: [API.md](API.md#permissions).
- **Group folders** - a folder that belongs to a *group* instead of one
  person: a shared workspace with its own quota, managed membership with
  manager/member roles (administrators create groups in the user
  administration), and one tree every member works directly - no
  individual shares involved. Group roots wear the group's badge in your
  root listing, folder keys travel from a manager to each member (the
  same envelope shape as a share's), and a group folder cannot be shared
  out to an individual. Details: [API.md](API.md#group-folders).
- **WebDAV** - mount your files with Nextcloud desktop clients, rclone,
  Cyberduck, Windows network drives (see [WebDAV](#webdav)).
- **Quotas** - 1 GiB per account by default, enforced with
  `507 Insufficient Storage`, usage shown in the topbar.
- **Trash** - deletions go to a per-user trash first; restore entries with
  one click, and everything older than 30 days is purged for good by a
  background sweep.

## Install

### One-line install & update

On any Linux with systemd and `curl` (as root):

```bash
curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | sh
```

That is both the install *and* the update command:

- **install** - creates the `fxcloud` system user, downloads the newest
  release binary (built and attached by GitHub Actions), writes a hardened
  systemd unit, enables and starts the service.
- **update** - running the same line again replaces only the binary (the
  previous one is kept as `/home/fxcloud/fxcloud.bak`) and restarts. The
  unit and the data directory are never touched.

The first line prints `fxcloud v... is running` once
`http://<host>:8080/login` answers. Open it and register: the **first
account** becomes the administrator.

Environment variables in front of the command configure the unit it writes
(all optional, defaults in brackets):

```bash
# example: public HTTPS address + bigger uploads
FXCLOUD_ORIGIN=https://cloud.example.com FXCLOUD_SECURE_COOKIE=1 \
FXCLOUD_MAX_UPLOAD_MB=4096 curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | sh
```

| Variable               | Meaning (default)                                          |
| ---------------------- | ---------------------------------------------------------- |
| `FXCLOUD_VERSION`      | release tag to install (latest)                            |
| `FXCLOUD_USER` / `FXCLOUD_HOME` / `FXCLOUD_DATA` | service user, its home, the data dir (`fxcloud`, `/home/fxcloud`, `.../data`) |
| `FXCLOUD_BIND` / `FXCLOUD_PORT` | listen address and port (`0.0.0.0`, `8080`)         |
| `FXCLOUD_ORIGIN`       | public URL for passkeys (unset)                            |
| `FXCLOUD_SECURE_COOKIE`| `1` for Secure cookies, behind HTTPS (unset)               |
| `FXCLOUD_MAX_UPLOAD_MB` / `FXCLOUD_TRASH_DAYS` / `FXCLOUD_SESSION_TTL` | upload limit, trash lifetime, session TTL (`1024`, `30`, `604800`) |
| `RUST_LOG`             | log filter (`fxcloud=info`)                                |

Afterwards the knobs live in the unit file: edit
`/etc/systemd/system/fxcloud.service` and `systemctl restart fxcloud`.
Pin a version with `FXCLOUD_VERSION=v0.0.25`; other platforms (macOS,
ARM64, ...) build from source or run the Docker image below.

### Prebuilt binary

Every tagged release on [GitHub
Releases](https://github.com/floyd54/fxcloud/releases) ships a fully
static Linux x86_64 build (~6 MB, no runtime dependencies):

```bash
chmod +x fxcloud-<tag>-x86_64-unknown-linux-musl
FXCLOUD_DATA=/srv/fxcloud ./fxcloud-<tag>-x86_64-unknown-linux-musl
```

Every release page carries notes on what changed and why it matters;
the texts are committed next to the code in [`notes/`](notes/) and
attached automatically when the release is tagged.

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
| `FXCLOUD_SESSION_TTL`   | `604800`        | Session lifetime in seconds (7 days, sliding renewal)|
| `FXCLOUD_SECURE_COOKIE` | `false`         | Set `Secure` on cookies (enable behind HTTPS) |
| `FXCLOUD_MAX_UPLOAD_MB` | `1024`          | Max request body for uploads, in MiB |
| `FXCLOUD_TRASH_DAYS`    | `30`            | Days a trashed entry is kept before the purge removes it |
| `FXCLOUD_TRASH_SWEEP_SECS` | `3600`       | Interval of the trash purge sweep, in seconds |
| `FXCLOUD_ORIGIN`          | (derived)    | Public origin for WebAuthn passkeys (e.g. `https://cloud.example.com`); defaults to the request's scheme and `Host` |
| `RUST_LOG`              | `fxcloud=info`  | Log filter (tracing)                 |

```bash
FXCLOUD_BIND=0.0.0.0 FXCLOUD_PORT=9000 FXCLOUD_DATA=/srv/fxcloud ./fxcloud
```

## Deployment

### systemd

The [one-liner above](#one-line-install--update) writes this unit for you.
To place fxcloud by hand - e.g. a build from source - the provided
hardened unit ([`deploy/fxcloud.service`](deploy/fxcloud.service)) runs as
an unprivileged system user, never as root:

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
`sudo systemctl start fxcloud` - or just run the one-liner again.

### Docker

The repository carries a [`Dockerfile`](Dockerfile): a multi-stage build
(Rust on Alpine -> ~8 MB runtime image, the binary runs as a non-root user
and has a health check on `/login`). Build and run:

```bash
docker build -t fxcloud .

docker run -d --name fxcloud \
  -p 8080:8080 \
  -v fxcloud-data:/data \
  fxcloud

open http://localhost:8080    # first account becomes the admin
```

All the [configuration knobs](#configuration) are `-e` flags; behind a
reverse proxy add `-e FXCLOUD_ORIGIN=https://cloud.example.com -e
FXCLOUD_SECURE_COOKIE=1`. Data (database + file blobs) lives in the
`/data` volume and survives rebuilds:

```bash
docker stop fxcloud && docker rm fxcloud
docker build -t fxcloud .    # update = rebuild, the volume keeps the data
docker run -d --name fxcloud -p 8080:8080 -v fxcloud-data:/data fxcloud
```

Logs: `docker logs -f fxcloud`. A bind mount works the same way
(`-v /srv/fxcloud:/data`, chown it to the container user first).

### Behind a reverse proxy (HTTPS)

fxcloud speaks plain HTTP, so the proxy must terminate TLS - and allow
large uploads:

- **Set `FXCLOUD_ORIGIN`** to the exact URL users open fxcloud under, e.g.
  `FXCLOUD_ORIGIN=https://cloud.example.com`. Passkeys verify the browser's
  `Origin` against it; without it fxcloud derives the origin from the
  forwarded scheme and `Host`, which is only right when the proxy passes
  both unchanged. Scheme, host and port must match what the browser sends -
  no trailing slash. A mismatch is refused with
  `Origin does not match this server's address - set FXCLOUD_ORIGIN to the
  URL users open it under`.
- Raise the body-size limit (nginx: `client_max_body_size 10G;`) and keep
  it in sync with `FXCLOUD_MAX_UPLOAD_MB` - a file must be under both.
- Forward `Host`, `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`.
- Set `FXCLOUD_SECURE_COOKIE=1` so cookies get the `Secure` attribute.

A public deployment needs both halves - HTTPS (browsers only expose
passkeys in a secure context) and the exact `FXCLOUD_ORIGIN` - and
fxcloud says so itself: listening beyond loopback without the knob logs
a WARN at startup naming the bind address, because the derived origin
breaks silently behind a proxy that rewrites `Host`.

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

The **first account** created on an instance becomes its administrator: it is
activated immediately and carries the `is_admin` flag. Every account created
after that starts inactive and non-admin. An administrator opens **User
administration** from the menu behind their name in the top bar to:

* **activate / deactivate** accounts (takes effect instantly: sessions and
  WebDAV included; an admin cannot deactivate themselves),
* **grant / revoke the administrator role** (the last active administrator can
  neither be deactivated nor demoted),
* **set the storage quota** per account,
* **reset a password**, which hands back a one-time generated temporary
  password for the user's next sign-in.

The same switches are still available directly in the database (no restart
required). On a systemd deployment the file is
`/home/fxcloud/data/fxcloud.db`, in development `./data/fxcloud.db`:
*Display name, theme and password are not on this list: every user changes
those themselves in the app, via the menu behind their name in the top bar.*

```bash
DB=/home/fxcloud/data/fxcloud.db

# overview
sqlite3 "$DB" "SELECT id, username, is_active, is_admin, quota_bytes FROM users ORDER BY id;"

# activate / deactivate (takes effect instantly: sessions + WebDAV included)
sqlite3 "$DB" "UPDATE users SET is_active = 1 WHERE username = 'max';"
sqlite3 "$DB" "UPDATE users SET is_active = 0 WHERE username = 'max';"

# administrator role
sqlite3 "$DB" "UPDATE users SET is_admin = 1 WHERE username = 'max';"

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
cargo test          # unit tests: permissions, quota, group roles, KDF floor,
                    # filename and RFC 5987 encoding, session-cookie parsing
./tests/suite.sh    # integration: 663 checks against a throwaway instance
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

- [USERGUIDE.md](USERGUIDE.md) - the user's guide: install, files, sharing,
  trash, quotas, encryption, passkeys, HTTPS/reverse proxy with
  `FXCLOUD_ORIGIN`, WebDAV, troubleshooting
- [ENCRYPTION.md](ENCRYPTION.md) - client-side per-file encryption: threat
  model, cryptographic design, the DECISIONs behind it, and the phases
- [ARCHITECTURE.md](ARCHITECTURE.md) - code layout, storage format,
  permission and quota model
- [API.md](API.md) - HTTP endpoints, batch/ZIP semantics, WebDAV details

## License

MIT
