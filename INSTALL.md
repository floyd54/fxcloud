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

On a terminal the script asks one question before it installs anything:

```text
office hostname (e.g. office.example.com, Enter to skip):
```

**Explicit recommendation: press Enter and start without office
integration.** It retrofits later with one rerun of the same line plus
the office hostname ([Office integration](#office-integration-optional))
- at the beginning it only makes the installation more complicated than
it has to be.

Environment variables configure the unit the script writes (all optional,
defaults in brackets). They have to reach the script itself: `export` them
before the one-liner, or place them in front of `sh` *behind* the pipe. In
front of `curl` they would only reach curl, never the script:

```bash
# example: public HTTPS address + bigger uploads
export FXCLOUD_ORIGIN=https://cloud.example.com FXCLOUD_SECURE_COOKIE=1 \
  FXCLOUD_MAX_UPLOAD_MB=4096
curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | sh
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
Pin a version with `FXCLOUD_VERSION=v0.2.0`; other platforms (macOS,
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

## Office integration (optional)

Office documents (docx, xlsx, pptx, odt, ods, odp) can be opened and
edited in the browser through an office engine - **Euro-Office**,
**OnlyOffice** or **Collabora CODE** - that fxcloud drives over the WOPI
protocol ([concepts/office.md](concepts/office.md) has the design, the
spike results and the implementation notes).

This is an **addition, never a requirement**. Unless `FXCLOUD_OFFICE_URL`
is set, none of it exists: no routes, no CSP change, no UI, no cost -
and everything else on this page keeps working exactly as before.

> **Explicit recommendation: start without office integration.** Get
> fxcloud running first; office is an add-on you retrofit later, when you
> actually need it - and that is deliberately easy: run the same one-liner
> again with the office hostname ([Office via install.sh](#office-via-installsh)),
> it wires office into an already installed instance. Starting out with
> office makes the first installation unnecessarily more complicated:
> Docker must be in place, a second reverse-proxy entry and an image
> download come into play, and the engine reserves its RAM from the very
> first minute.

### What it costs

| Where you run | What to budget |
|---|---|
| **32 GB instance** | Runs it without noticing - the engine is a rounding error next to fxcloud. |
| **Any box with RAM to spare** | **+4 GB RAM** for the engine container covers all three engines: Collabora CODE idles around 1.3 GB (+~100 MB per concurrent user); the OnlyOffice-class engines are sized **4 GB RAM / 40 GB disk** by their vendor guidance. Plus ~2 GB of image and engine cache. |
| **1-2 GB VPS** | Runs **without Office - that is a supported configuration, not a missing feature.** The documented answer is the WebDAV mount ([USERGUIDE](USERGUIDE.md#14-webdav)): `rclone`, a Windows network drive or the Finder open the same tree in LibreOffice/Word with full fidelity. Office editing is for instances with RAM to spare, never a requirement. |

### Office via install.sh

The one-liner can do everything below. Run it on a terminal and it asks:

```text
office hostname (e.g. office.example.com, Enter to skip):
```

The name is the **public** origin of the editor (the proxy entry you make
anyway), e.g. `office.example.com` - `https://` is added if you leave it
out, Enter skips office entirely. Non-interactive (or to skip the question)
pass it in front of `sh` behind the pipe:

```bash
curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | \
  FXCLOUD_OFFICE_URL=https://office.example.com sh
```

With a hostname the script, in one run:

- **requires Docker** (`command -v docker` + `docker info`) and stops with a
  clear message if it is missing - it never installs Docker itself;
- generates the WOPI secret, starts the `fxcloud-office` container with your
  own landing page bind-mounted from `$FXCLOUD_HOME/office` (see below), and
  waits until the editor answers;
- **adds the `FXCLOUD_OFFICE_*` lines to the unit - also to an
  existing unit**, so plain updates on an installed fxcloud gain office
  without touching anything else (rerun-proof, existing values are kept);
- **prints where the engine listens**: the raw port mapping (e.g.
  `0.0.0.0:8010`) as soon as the container is up - the exact number the
  reverse proxy needs, no `ss` digging - and both proxy targets (localhost
  and this host) again in the final summary.

What stays manual: the reverse proxy entry for the office name (websocket
upgrade + TLS) - covered under Reverse proxy below.

| Variable | Meaning (default) |
| --- | --- |
| `FXCLOUD_OFFICE_URL` | public editor origin; asked interactively when omitted (Enter = no office) |
| `FXCLOUD_OFFICE_SECRET` | WOPI token key (generated when omitted, kept on reruns) |
| `FXCLOUD_OFFICE_IMAGE` | engine `image:tag` (the release in Run the engine); a different tag = engine update on rerun |
| `FXCLOUD_OFFICE_PORT` | host port published for the engine (8010) |
| `FXCLOUD_OFFICE_NETWORK` | `auto` (default: publish the port, fall back to `host` where the runtime refuses it, e.g. nested/LXC), `bridge` or `host` |
| `FXCLOUD_OFFICE_WOPI_BASE` | fxcloud URL as the engine sees it (derived from the container network when omitted) |

Everything from **The three connections** down describes what the script
does for you - use it for reference and for manual setups.

### The three connections

```text
Browser -- session, files -----------------------> fxcloud
   |
   +-- editor iframe + websocket ----------------> office engine
   |                                                (public origin,
   |                                                 TLS + websockets)
   +-- (mints editor URL + token via POST /api/office/start)

office engine -- WOPI (server-side) -------------> fxcloud
              CheckFileInfo / GetFile / PutFile
              (internal address - bypasses the proxy)
```

1. **Browser -> fxcloud**: unchanged. The only new endpoint is
   `POST /api/office/start`, which mints the editor URL and a short-lived
   WOPI access token (HMAC, fxcloud-side secret).
2. **Browser -> office engine**: the editor runs in an iframe on an
   fxcloud page, but its UI assets and websocket come from the engine.
   That origin must be **HTTPS** once fxcloud itself is HTTPS (mixed
   content forbids an http iframe on an https page), and the proxy must
   pass **websocket upgrades**.
3. **Office engine -> fxcloud**: the WOPI calls happen server-side
   inside the engine container. It needs an address for fxcloud the
   *container* can reach - usually not the public URL.

### Configure fxcloud

```bash
# one shared secret, minted once, pasted into the fxcloud unit
FXCLOUD_OFFICE_SECRET=$(openssl rand -hex 32)
```

| Variable | Meaning |
|---|---|
| `FXCLOUD_OFFICE_URL` | engine base URL **as the browser sees it** (the iframe source). Unset = feature off. |
| `FXCLOUD_OFFICE_SECRET` | HMAC key for the WOPI access tokens. Required with the URL; fxcloud refuses to start without it. |
| `FXCLOUD_OFFICE_WOPI_BASE` | fxcloud URL **as the engine container sees it** (default: `FXCLOUD_ORIGIN`). This is the WOPI leg - it should *not* go through the proxy. |
| `FXCLOUD_OFFICE_EMBED` | `form` (default - the official host-page POST, the OnlyOffice/Euro-Office flow) or `iframe` (Collabora's query-string flow). |

```ini
# /etc/systemd/system/fxcloud.service, [Service] section
Environment=FXCLOUD_OFFICE_URL=https://office.example.com
Environment=FXCLOUD_OFFICE_SECRET=...the generated value...
Environment=FXCLOUD_OFFICE_WOPI_BASE=http://172.17.0.1:8080
```

### Run the engine

```bash
# Collabora CODE - no JWT, the alias group is the host allow list
docker run -d --name fxcloud-office --restart unless-stopped \
  -p 9980:9980 \
  -e aliasgroup1="http://fxcloud.example.com:8080" collabora/code

# Euro-Office / OnlyOffice - WOPI on, private addresses allowed for the
# internal WOPI base, JWT off (the WOPI access token authenticates instead)
docker run -d --name fxcloud-office --restart unless-stopped \
  -p 8010:80 \
  -e WOPI_ENABLED=true -e ALLOW_PRIVATE_IP_ADDRESS=true -e JWT_ENABLED=false \
  nextcloud/aio-eurooffice:20261029_171813
```

(The OnlyOffice-class engines block private addresses by default -
`ALLOW_PRIVATE_IP_ADDRESS=true` lifts the private address block, which is
what the internal WOPI base (`172.17.0.1`, `127.0.0.1`) needs;
`JWT_ENABLED=false` keeps the DocumentServer's own JWT layer out of the
WOPI flow. An `IP_FILTER_RULES` rule is **not** needed: this image never
reads that variable, and its own `ipfilter.useforrequest` stays `false`.
Set `FXCLOUD_OFFICE_WOPI_BASE` to the address the engine container can
reach: a Docker network name, `host.docker.internal`, or an internal IP.)

`--restart unless-stopped` matters: without it a reboot leaves the engine
stopped while fxcloud comes back up, and every office button fails until
you notice.

### The landing page (branding)

The bare engine serves its own welcome page (and a version banner at
`/index.html`). Two bind mounts replace both with your own files - kept on
the **host**, so they survive every image update and container
recreation. Mount the welcome **directory**, not single files: the
engine's entrypoint rewrites those pages with `sed -i` on every start
under `set -e`, which fails on a read-only single-file mount and kills
the container:

```bash
ENGINE_DIR=/home/fxcloud/office        # install.sh uses $FXCLOUD_HOME/office
mkdir -p "$ENGINE_DIR/welcome"
cat > "$ENGINE_DIR/welcome/docker.html" <<'EOF'
<!DOCTYPE html>
<html lang="de">
<head><meta charset="utf-8"><title>fxcloud</title></head>
<body>
  <h1>fxcloud</h1>
  <p>Office-Endpunkt &ndash; Dokumente bearbeitest du in fxcloud.</p>
  <p><a href="https://cloud.example.com/">Zu fxcloud</a></p>
</body>
</html>
EOF
cat > "$ENGINE_DIR/ds-branding.conf" <<'EOF'
location = /index.html { return 200 "OK"; }
# the landing page is hand-edited - never let browsers cache it for a year
location = /welcome/ {
  alias /var/www/euro-office/documentserver-example/welcome/docker.html;
  default_type text/html;
  expires -1;
}
EOF
```

Add both mounts to the `docker run` above:

```text
  -v /home/fxcloud/office/welcome:/var/www/euro-office/documentserver-example/welcome \
  -v /home/fxcloud/office/ds-branding.conf:/etc/nginx/includes/ds-branding.conf \
```

- `docker.html` is what `/` and `/welcome/` serve (nginx `index`); any page
  you do not create simply404s - no foreign branding under your domain;
- `ds-branding.conf` is picked up by nginx's `ds-*.conf` include and turns
  the version banner at `/index.html` into `200 OK`;
- install.sh seeds `docker.html`, `example-disabled.html`,
  `admin-disabled.html` and `ds-branding.conf` when they are missing -
  your edits are never overwritten by a rerun or an engine update;
- the link back to fxcloud targets `FXCLOUD_ORIGIN` (unit line or knob)
  when install.sh seeds it; a seed from before that still points at `/` -
  the next run retargets exactly that one line and nothing else you wrote;
- the engine serves the welcome path with a one-year cache
  (`expires365d`), so both conf versions above override it with
  `no-cache`. A copy your browser already cached keeps showing the old
  page until you hard-refresh once (Ctrl+Shift+R / Cmd+Shift+R).

### Updating the engine

Nothing of the office setup lives inside the image: URL, secret and WOPI
base are unit lines, the landing page is on the host. So an update is
pull + recreate with the same flags and mounts:

```bash
docker pull nextcloud/aio-eurooffice:<new-tag>
docker rm -f fxcloud-office            # in-flight editor sessions are lost
docker run -d ...                      # same command as above, new tag
```

Or in one line with install.sh (also reconciles container, mounts and
unit):

```bash
curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | \
  FXCLOUD_OFFICE_IMAGE=nextcloud/aio-eurooffice:<new-tag> sh
```

### Reverse proxy

The WOPI leg does **not** need to be served by the proxy - point
`FXCLOUD_OFFICE_WOPI_BASE` at an internal address and the token-bearing
traffic never touches the public path (no hairpin NAT, nothing in the
public access log). Only the editor UI goes through the proxy:

- a **second hostname** (`office.example.com`) is the robust shape, a
  dedicated port (`https://example.com:8443`) works without extra DNS; a
  path prefix (`/office/`) is **not** reliable - the engines assume a
  root deployment;
- **websocket upgrade headers** (`Upgrade`/`Connection`) on the engine
  location; the fxcloud location needs none of that;
- **body limit**: PutFile travels engine -> fxcloud. In the default
  shape it bypasses the proxy entirely; if you split networks and proxy
  `/wopi/*` (below), it lands on the fxcloud location - whose
  `client_max_body_size` already covers `FXCLOUD_MAX_UPLOAD_MB`, so one
  setting handles browser uploads and PutFile alike;
- **`Host` / `X-Forwarded-*`** pass-through so the engine emits its own
  asset URLs under `FXCLOUD_OFFICE_URL`;
- **log hygiene**: Collabora carries `WOPISrc` *and* `access_token` in
  the editor iframe's query string - keep tokens short-lived (10 h by
  default) and consider not logging query strings on the engine location.

**Split-network exception**: only when the engine cannot reach fxcloud
directly (separate machines or firewalls) proxy `/wopi/*` as a plain
reverse-proxy block - no websockets needed there, and keep it on a
private network or VPN if possible.

### Verify the setup

1. `journalctl -u fxcloud -f` - the unit must start with no
   `FXCLOUD_OFFICE_SECRET is required` refusal.
2. Open any `.docx` in the file list - the row now opens the editor
   overlay instead of staying inert.
3. Type, close the editor, refresh: the size and "modified at" of the
   row changed, and **Settings > Version history** (or the row menu)
   shows one new version - that is the save round trip through WOPI.
4. `journalctl -u fxcloud -f` again: no404 from the engine's WOPI calls.
5. Open the office hostname directly in a browser: your own landing page
   appears (not the engine's welcome page) and its link back reaches
   fxcloud - hard-refresh once (Ctrl+Shift+R) if the browser still shows
   an old cached copy.

### Troubleshooting

- **`failed to start container process: ... ip_unprivileged_port_start:
  permission denied`** - seen on LXC containers: `-p` port publishing
  triggers a sysctl write the nested environment refuses. Use
  `--network host` for the engine container instead (and put the engine's
  port into `FXCLOUD_OFFICE_URL`). install.sh does this automatically:
  its default `FXCLOUD_OFFICE_NETWORK=auto` retries with `--network host`
  when publishing fails (then the engine needs port 80 on the host).
- **`DNS lookup ... is not allowed. Because, It is private IP address`**
  (in the engine's log): the engine refuses the internal WOPI base -
  `-e ALLOW_PRIVATE_IP_ADDRESS=true` lifts the private address block
  (nothing else is required for WOPI on this image).
- **The editor iframe stays blank / " refused to connect"**: mixed
  content (the page is https, the engine http) or the proxy lacks the
  websocket upgrade headers.
- **`cannot derive the WOPI base URL`** at mint time: set
  `FXCLOUD_OFFICE_WOPI_BASE` (or `FXCLOUD_ORIGIN`) so the engine's
  server-side calls have a reachable address.
- **After an engine upgrade the `iframe` embed stops** (Collabora's
  `cool.html` lives behind a build-hashed path in discovery): re-copy the
  current path into `FXCLOUD_OFFICE_URL`, or use `FXCLOUD_OFFICE_EMBED=form`.
- **Every office button says "Could not open the office editor"**: the
  engine is down (`docker ps`), the URL/secret mismatch between the two
  sides, or the file is encrypted (office editing works on plaintext -
  the built-in editor handles encrypted files).
- **install.sh: `office was requested, but docker is not installed`** -
  by design the script never installs Docker. Install it yourself
  (docs.docker.com/engine/install/) and re-run.
- **install.sh never asks for the office hostname** - the prompt only
  appears on a real terminal (`/dev/tty`); in automated runs pass the
  name in front of `sh` behind the pipe (see Office via install.sh).
