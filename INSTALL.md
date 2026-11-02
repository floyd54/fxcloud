# Installing fxcloud

Everything about *running* fxcloud: the one-liner, prebuilt binaries,
building from source, the configuration knobs, systemd, Docker and the
reverse-proxy setup. For using it afterwards, see the
[User Guide](USERGUIDE.md); for the feature documents, start at the
[README](README.md).

## One-line install & update

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
Pin a version with `FXCLOUD_VERSION=v0.1.6`; other platforms (macOS,
ARM64, ...) build from source or run the Docker image below.

## Prebuilt binary

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

## From source

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
