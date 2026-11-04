#!/bin/sh
# fxcloud - one line installs it, the same line updates it:
#
#   curl -fsSL https://raw.githubusercontent.com/floyd54/fxcloud/main/install.sh | sh
#
# What it does
#   install  creates the system user and its home, downloads the newest
#            release binary (built and attached by GitHub Actions), writes a
#            hardened systemd unit, enables and starts the service.
#   update   replaces only the binary - the previous one is kept as
#            $FXCLOUD_HOME/fxcloud.bak - and restarts. The data directory
#            is never touched.
#   office   (opt-in) once an office hostname is known - from the unit, the
#            FXCLOUD_OFFICE_URL knob, or an interactive prompt - it generates
#            the WOPI secret, starts the office engine container with your
#            own landing page bind-mounted from $FXCLOUD_HOME/office, adds
#            the FXCLOUD_OFFICE_* unit lines (also to an existing unit) and
#            waits until the engine answers. Docker must already be
#            installed - this script never installs it.
#
# Knobs (environment variables for the script, all optional). They have to
# reach the script: `export VAR=...` before the one-liner, or directly in
# front of `sh` behind the pipe (`curl -fsSL ... | VAR=... sh`). In front of
# `curl` they would only reach curl, never this script:
#   FXCLOUD_VERSION        release tag to install (default: latest)
#   FXCLOUD_USER           system user (default: fxcloud)
#   FXCLOUD_HOME           home of that user (default: /home/$FXCLOUD_USER)
#   FXCLOUD_DATA           data directory (default: $FXCLOUD_HOME/data)
#   FXCLOUD_BIND           listen address (default: 0.0.0.0)
#   FXCLOUD_PORT           listen port (default: 8080)
#   FXCLOUD_ORIGIN         public origin for passkeys, e.g. https://cloud.example.com
#   FXCLOUD_SECURE_COOKIE  1 to mark cookies Secure (use behind HTTPS)
#   FXCLOUD_MAX_UPLOAD_MB  largest upload in MiB (default: 1024)
#   FXCLOUD_TRASH_DAYS     days a trashed entry is kept (default: 30)
#   FXCLOUD_SESSION_TTL    session lifetime in seconds (default: 604800 = 7 days, sliding)
#   RUST_LOG               log filter (default: fxcloud=info)
#   FXCLOUD_OFFICE_URL     office editor origin, e.g. https://office.example.com
#                          (asked interactively when omitted; Enter = no office)
#   FXCLOUD_OFFICE_SECRET  WOPI token key (generated when omitted)
#   FXCLOUD_OFFICE_IMAGE   office engine image:tag (default: the Euro-Office
#                          release documented in INSTALL.md; setting a
#                          different tag updates a running engine container)
#   FXCLOUD_OFFICE_PORT    host port published for the engine (default: 8010)
#   FXCLOUD_OFFICE_NETWORK auto (default), bridge or host - how the engine
#                          container reaches the network; "auto" publishes
#                          FXCLOUD_OFFICE_PORT and falls back to the host
#                          network where the runtime refuses publishing
#                          (nested/LXC hosts)
#   FXCLOUD_OFFICE_WOPI_BASE  fxcloud URL as the engine container sees it
#                          (default: derived from the container network)
#
# The knobs configure the unit on a fresh install only; the office lines are
# the exception - they are added whenever missing. Afterwards edit
# /etc/systemd/system/fxcloud.service and `systemctl restart fxcloud`.
set -eu

REPO="${FXCLOUD_REPO:-floyd54/fxcloud}"
USER_NAME="${FXCLOUD_USER:-fxcloud}"
HOME_DIR="${FXCLOUD_HOME:-/home/$USER_NAME}"
DATA_DIR="${FXCLOUD_DATA:-$HOME_DIR/data}"
BIN="$HOME_DIR/fxcloud"
UNIT=/etc/systemd/system/fxcloud.service

log() { printf '==> %s\n' "$*"; }
die() { printf 'error: %s\n' "$*" >&2; exit 1; }

# ---- preflight ------------------------------------------------------------
[ "$(id -u)" -eq 0 ] || die "must run as root: curl -fsSL ... | sudo sh"
command -v curl >/dev/null 2>&1 || die "curl is required"
command -v timeout >/dev/null 2>&1 || die "coreutils timeout is required"
command -v systemctl >/dev/null 2>&1 || die "systemd is required"

# ---- office request (opt-in, resolved before anything is touched) --------
# Sources in order: an already configured unit (an update never re-asks),
# the FXCLOUD_OFFICE_URL knob, then an interactive prompt. The prompt reads
# from /dev/tty, never from stdin - under `curl ... | sh` stdin is this
# script itself. No hostname from any source means: no office, exactly as
# without this feature.
OFFICE_URL_IN_UNIT=""
if [ -f "$UNIT" ]; then
  OFFICE_URL_IN_UNIT=$(sed -n 's/^Environment=FXCLOUD_OFFICE_URL=//p' "$UNIT" | head -n 1)
fi
OFFICE_URL="$OFFICE_URL_IN_UNIT"
if [ -z "$OFFICE_URL" ]; then
  OFFICE_URL="${FXCLOUD_OFFICE_URL:-}"
fi
# where the landing page sends visitors back to: the origin the running
# service uses (an existing unit wins, like everywhere else), else the
# FXCLOUD_ORIGIN knob; without a usable value the button links to "/"
# and the summary says how to fix that
OFFICE_LINK="${FXCLOUD_ORIGIN:-}"
if [ -f "$UNIT" ]; then
  OFFICE_LINK_IN_UNIT=$(sed -n 's/^Environment=FXCLOUD_ORIGIN=//p' "$UNIT" | head -n 1)
  if [ -n "$OFFICE_LINK_IN_UNIT" ]; then
    OFFICE_LINK="$OFFICE_LINK_IN_UNIT"
  fi
fi
OFFICE_LINK=$(printf '%s' "$OFFICE_LINK" | tr -d '\r\n')
[ -n "$OFFICE_LINK" ] || OFFICE_LINK="/"
if [ -z "$OFFICE_URL" ] && ( : </dev/tty ) 2>/dev/null; then
  printf 'office hostname (e.g. office.example.com, Enter to skip): '
  OFFICE_ANSWER=""
  read -r OFFICE_ANSWER < /dev/tty || OFFICE_ANSWER=""
  case "$OFFICE_ANSWER" in
    "") ;;
    *://*) OFFICE_URL="$OFFICE_ANSWER" ;;
    *) OFFICE_URL="https://$OFFICE_ANSWER" ;;
  esac
fi
if [ -n "$OFFICE_URL" ]; then
  # Windows/PuTTY line ends break the unit line silently - strip them here
  OFFICE_URL=$(printf '%s' "$OFFICE_URL" | tr -d '\r\n')
fi
if [ -n "$OFFICE_URL" ]; then
  case "$OFFICE_URL" in
    http://?*|https://?*) ;;
    *) die "office URL must start with http:// or https:// (got: $OFFICE_URL)" ;;
  esac
  case "$OFFICE_URL" in
    *[[:space:]]*) die "office URL must not contain spaces (got: $OFFICE_URL)" ;;
  esac
fi
if [ -n "$OFFICE_URL_IN_UNIT" ] && [ -n "${FXCLOUD_OFFICE_URL:-}" ] &&
  [ "$OFFICE_URL_IN_UNIT" != "$FXCLOUD_OFFICE_URL" ]; then
  log "office: unit already configured with $OFFICE_URL_IN_UNIT - keeping it (edit $UNIT to change)"
fi
if [ -n "$OFFICE_URL" ]; then
  # docker is a hard requirement here - this script never installs it
  command -v docker >/dev/null 2>&1 ||
    die "office was requested, but docker is not installed. Install Docker yourself (https://docs.docker.com/engine/install/) and re-run - this script never installs Docker"
  docker info >/dev/null 2>&1 ||
    die "office was requested, but the docker daemon does not respond. Start it (systemctl start docker) and re-run"
  log "office: $OFFICE_URL"
fi

# ---- pick the release -----------------------------------------------------
TAG="${FXCLOUD_VERSION:-}"
if [ -z "$TAG" ]; then
  log "looking up the latest release"
  TAG=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" |
    sed -n 's/.*"tag_name": *"\([^"]*\)".*/\1/p' | head -n 1)
  [ -n "$TAG" ] || die "cannot reach the GitHub releases of $REPO"
fi
case "$TAG" in v*) ;; *) TAG="v$TAG" ;; esac
ASSET_URL="https://github.com/$REPO/releases/download/$TAG/fxcloud-$TAG-x86_64-unknown-linux-musl"

# ---- download and sanity-check --------------------------------------------
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
log "downloading $TAG"
curl -fsSL --retry 3 "$ASSET_URL" -o "$TMP/fxcloud" ||
  die "download failed: $ASSET_URL"
# ---- checksum against what the release publishes ---------------------------
# SHA256SUMS rides the release as a second asset, written by CI in the
# standard sha256sum format (hash, two spaces, file name). Releases
# before v0.0.34 carry none: those keep installing on the ELF and
# --version checks below, so a missing file is a note, never a failure -
# but a file that is present and does not match must end the install.
SUMS_URL="https://github.com/$REPO/releases/download/$TAG/SHA256SUMS"
ASSET_NAME="fxcloud-$TAG-x86_64-unknown-linux-musl"
if ! command -v sha256sum >/dev/null 2>&1; then
  log "no sha256sum on this host - relying on the ELF and --version checks"
elif curl -fsSL --retry 3 "$SUMS_URL" -o "$TMP/SHA256SUMS" 2>/dev/null; then
  WANT=$(awk -v n="$ASSET_NAME" '$2 == n {print $1; exit}' "$TMP/SHA256SUMS")
  [ -n "$WANT" ] ||
    die "SHA256SUMS does not mention $ASSET_NAME - refusing an unchecksummed download"
  GOT=$(sha256sum "$TMP/fxcloud" | awk '{print $1}')
  [ "$GOT" = "$WANT" ] ||
    die "checksum mismatch: the download does not match the release's SHA256SUMS"
  log "checksum verified against SHA256SUMS"
else
  log "no SHA256SUMS for $TAG (pre-v0.0.34 release) - relying on the ELF and --version checks"
fi
head -c 4 "$TMP/fxcloud" | od -An -tx1 | grep -q '7f 45 4c 46' ||
  die "the download is not an ELF binary"
chmod 755 "$TMP/fxcloud"
# timeout: a release from before v0.0.25 has no --version, and a foreign
# architecture fails to exec - both must end here, not hang or start
# anything.
timeout 5 "$TMP/fxcloud" --version >/dev/null 2>&1 ||
  die "cannot verify the binary: it does not run here (prebuilt is x86_64) or predates --version (v0.0.25+)"
NEW=$(timeout 5 "$TMP/fxcloud" --version | sed -n '/^fxcloud v/p' | head -n 1)
[ -n "$NEW" ] || NEW="fxcloud vX.Y.Z"

# ---- user and directories -------------------------------------------------
if id "$USER_NAME" >/dev/null 2>&1; then
  log "using existing user $USER_NAME"
else
  log "creating system user $USER_NAME"
  useradd --system --create-home --home-dir "$HOME_DIR" --user-group \
    --shell /usr/sbin/nologin "$USER_NAME" ||
    die "could not create user $USER_NAME"
fi
mkdir -p "$DATA_DIR"
chown -R "$USER_NAME" "$HOME_DIR"
chmod 750 "$HOME_DIR"

# ---- binary (an update keeps the previous one) ----------------------------
if [ -x "$BIN" ]; then
  # timeout: a binary from before v0.0.25 has no --version flag and would
  # start a server here instead of answering.
  OLD=$(timeout 5 "$BIN" --version 2>/dev/null | sed -n '/^fxcloud v/p' | head -n 1)
  [ -n "$OLD" ] || OLD="fxcloud (pre-v0.0.25)"
  log "updating: $OLD -> $NEW"
  cp -p "$BIN" "$BIN.bak"
else
  log "installing $NEW"
fi
install -m 755 -o "$USER_NAME" -g "$(id -gn "$USER_NAME")" "$TMP/fxcloud" "$BIN"

# ---- office engine (opt-in, only with an office hostname) ----------------
# Creates or reconciles the engine container. The branding files live on the
# host under $FXCLOUD_HOME/office and are bind-mounted, so they survive every
# image update; only missing files are seeded, your edits are kept. Network:
# "auto" publishes FXCLOUD_OFFICE_PORT and falls back to the host network
# where the runtime refuses publishing (nested/LXC hosts) - the engine then
# occupies port 80 on this machine.
if [ -n "$OFFICE_URL" ]; then
  OFFICE_DIR="$HOME_DIR/office"
  OFFICE_IMAGE="${FXCLOUD_OFFICE_IMAGE:-nextcloud/aio-eurooffice:20261029_171813}"
  OFFICE_PPORT="${FXCLOUD_OFFICE_PORT:-8010}"
  OFFICE_NET="${FXCLOUD_OFFICE_NETWORK:-auto}"
  case "$OFFICE_NET" in
    auto | bridge | host) ;;
    *) die "FXCLOUD_OFFICE_NETWORK must be auto, bridge or host (got: $OFFICE_NET)" ;;
  esac
  case "${FXCLOUD_OFFICE_EMBED:-}" in
    "" | form | iframe) ;;
    *) die "FXCLOUD_OFFICE_EMBED must be form or iframe (got: $FXCLOUD_OFFICE_EMBED)" ;;
  esac

  office_engine_run() {
    docker run -d --name fxcloud-office --restart unless-stopped \
      -e WOPI_ENABLED=true -e ALLOW_PRIVATE_IP_ADDRESS=true -e JWT_ENABLED=false \
      -v "$OFFICE_DIR/welcome:/var/www/euro-office/documentserver-example/welcome" \
      -v "$OFFICE_DIR/ds-branding.conf:/etc/nginx/includes/ds-branding.conf" \
      "$@" \
      "$OFFICE_IMAGE"
  }

  # seed your own landing page (only what is missing - never overwrite edits)
  mkdir -p "$OFFICE_DIR/welcome"
  if [ ! -f "$OFFICE_DIR/welcome/docker.html" ]; then
    cat > "$OFFICE_DIR/welcome/docker.html" <<'EOF'
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>fxcloud</title>
  <style>
    body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
           background: #0f1419; color: #e7eaee; margin: 0;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    main { text-align: center; padding: 2rem; max-width: 32rem; }
    h1 { font-size: 1.5rem; margin-bottom: .5rem; }
    p { color: #9aa4b2; line-height: 1.6; }
    a.btn { display: inline-block; margin-top: 1.25rem; padding: .6rem 1.4rem;
            background: #2563eb; color: #fff; text-decoration: none; border-radius: 6px; }
    a.btn:hover { background: #1d4ed8; }
  </style>
</head>
<body>
  <main>
    <h1>fxcloud</h1>
    <p>Dies ist der Office-Endpunkt von fxcloud. Dokumente bearbeitest du direkt in fxcloud &ndash; diese Seite ist nur der technische Hintergrund.</p>
    <a class="btn" href="/">Zu fxcloud</a>
  </main>
</body>
</html>
EOF
  fi
  if [ ! -f "$OFFICE_DIR/welcome/example-disabled.html" ]; then
    cat > "$OFFICE_DIR/welcome/example-disabled.html" <<'EOF'
<!DOCTYPE html>
<html lang="de">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>fxcloud</title>
  <style>
    body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif;
           background: #0f1419; color: #e7eaee; margin: 0;
           display: flex; align-items: center; justify-content: center; min-height: 100vh; }
    main { text-align: center; padding: 2rem; max-width: 32rem; }
    h1 { font-size: 1.5rem; margin-bottom: .5rem; }
    p { color: #9aa4b2; line-height: 1.6; }
    a { color: #60a5fa; }
  </style>
</head>
<body>
  <main>
    <h1>fxcloud</h1>
    <p>Diese Funktion ist deaktiviert.</p>
    <p><a href="/">Zur&uuml;ck zu fxcloud</a></p>
  </main>
</body>
</html>
EOF
  fi
  if [ ! -f "$OFFICE_DIR/welcome/admin-disabled.html" ]; then
    cp "$OFFICE_DIR/welcome/example-disabled.html" "$OFFICE_DIR/welcome/admin-disabled.html"
  fi
  # the landing page conf: index override + no-cache for a page you edit by
  # hand. The no-cache location matches the FINAL file URI: /welcome/ is
  # handled by the engine's own location and redirects to
  # /welcome/docker.html, so the index module never runs under our exact
  # match. An exact match on /welcome/ with alias to the FILE made nginx
  # stat "<file>index.html" per request -> ENOTDIR ->500.
  # Every write here is truncate-in-place (never sed -i): the conf is a
  # FILE bind mount, a rename silently decouples the container's view.
  OFFICE_CONF_CHANGED=0
  OFFICE_BRAND_CONF="$OFFICE_DIR/ds-branding.conf"
  if [ ! -f "$OFFICE_BRAND_CONF" ]; then
    cat > "$OFFICE_BRAND_CONF" <<'EOF'
location = /index.html { return 200 "OK"; }
# the landing page is hand-edited - never let browsers cache it for a year
location = /welcome/docker.html {
  alias /var/www/euro-office/documentserver-example/welcome/docker.html;
  expires -1;
}
EOF
  else
    # repair the block from the broken variant (our own comment + location)
    if grep -qF '# the landing page is hand-edited' "$OFFICE_BRAND_CONF" &&
      grep -qF 'location = /welcome/ {' "$OFFICE_BRAND_CONF"; then
      OFFICE_TMP="$OFFICE_BRAND_CONF.tmp"
      awk 'skip && /^}$/{skip=0; next}
           skip{next}
           /^# the landing page is hand-edited/{skip=1; next}
           {print}' "$OFFICE_BRAND_CONF" > "$OFFICE_TMP" &&
        cat "$OFFICE_TMP" > "$OFFICE_BRAND_CONF" &&
        rm -f "$OFFICE_TMP" ||
        die "cannot repair $OFFICE_BRAND_CONF - fix it by hand and re-run"
      OFFICE_CONF_CHANGED=1
      log "office: repaired the welcome block in ds-branding.conf (the old one made nginx answer500)"
    fi
    # a welcome block this script does not know would shadow the fixed one
    if grep -qF 'location = /welcome/ {' "$OFFICE_BRAND_CONF"; then
      die "$OFFICE_BRAND_CONF contains an unknown 'location = /welcome/' block (it makes nginx answer500) - remove it and re-run"
    fi
    if ! grep -qF 'location = /welcome/docker.html' "$OFFICE_BRAND_CONF" &&
      grep -qF 'location = /index.html' "$OFFICE_BRAND_CONF"; then
      cat >> "$OFFICE_BRAND_CONF" <<'EOF'

# the landing page is hand-edited - never let browsers cache it for a year
location = /welcome/docker.html {
  alias /var/www/euro-office/documentserver-example/welcome/docker.html;
  expires -1;
}
EOF
      OFFICE_CONF_CHANGED=1
      log "office: added no-cache for the landing page to ds-branding.conf"
    fi
  fi

  # earlier seeds linked back to the office origin itself ("/") - retarget
  # exactly those lines at fxcloud; anything else you wrote is untouched
  if [ "$OFFICE_LINK" != "/" ]; then
    OFFICE_LINK_SED=$(printf '%s' "$OFFICE_LINK" | sed 's/[&\\|]/\\&/g')
    OFFICE_MIGRATED=0
    for OFFICE_PAGE in "$OFFICE_DIR/welcome/"*.html; do
      [ -f "$OFFICE_PAGE" ] || continue
      if grep -qF '<a class="btn" href="/">Zu fxcloud</a>' "$OFFICE_PAGE" ||
        grep -qF '<a href="/">Zur&uuml;ck zu fxcloud</a>' "$OFFICE_PAGE"; then
        sed -i \
          -e "s|<a class=\"btn\" href=\"/\">Zu fxcloud</a>|<a class=\"btn\" href=\"$OFFICE_LINK_SED\">Zu fxcloud</a>|" \
          -e "s|<a href=\"/\">Zur&uuml;ck zu fxcloud</a>|<a href=\"$OFFICE_LINK_SED\">Zur\&uuml;ck zu fxcloud</a>|" \
          "$OFFICE_PAGE" ||
          die "cannot update the link in $OFFICE_PAGE - fix it by hand"
        OFFICE_MIGRATED=$((OFFICE_MIGRATED + 1))
      fi
    done
    if [ "$OFFICE_MIGRATED" -gt 0 ]; then
      log "office: landing page now links to $OFFICE_LINK ($OFFICE_MIGRATED pages)"
    fi
  fi
  chown -R "$USER_NAME" "$OFFICE_DIR"

  # WOPI secret: knob > existing unit > freshly generated (never rotated)
  OFFICE_SECRET="${FXCLOUD_OFFICE_SECRET:-}"
  if [ -z "$OFFICE_SECRET" ] && [ -f "$UNIT" ]; then
    OFFICE_SECRET=$(sed -n 's/^Environment=FXCLOUD_OFFICE_SECRET=//p' "$UNIT" | head -n 1)
  fi
  if [ -z "$OFFICE_SECRET" ]; then
    OFFICE_SECRET=$(od -An -N32 -tx1 /dev/urandom | tr -d ' \n')
    log "office: generated the WOPI secret"
  fi

  # container: keep it, update the image on explicit request, or create it
  OFFICE_MODE=""
  OFFICE_RECREATE=0
  if docker inspect fxcloud-office >/dev/null 2>&1; then
    OFFICE_CUR_IMAGE=$(docker inspect -f '{{.Config.Image}}' fxcloud-office)
    if [ "$OFFICE_CUR_IMAGE" != "$OFFICE_IMAGE" ]; then
      if [ -n "${FXCLOUD_OFFICE_IMAGE:-}" ]; then
        log "office: updating engine image $OFFICE_CUR_IMAGE -> $OFFICE_IMAGE"
        docker pull "$OFFICE_IMAGE" || die "cannot pull $OFFICE_IMAGE"
        docker stop fxcloud-office >/dev/null 2>&1 || true
        docker rm fxcloud-office || die "cannot remove the old engine container"
        OFFICE_RECREATE=1
      else
        log "office: engine container runs $OFFICE_CUR_IMAGE (set FXCLOUD_OFFICE_IMAGE=$OFFICE_IMAGE to update)"
      fi
    fi
  else
    OFFICE_RECREATE=1
  fi
  if [ "$OFFICE_RECREATE" = 1 ]; then
    case "$OFFICE_NET" in
    host)
      office_engine_run --network host ||
        die "engine failed to start with --network host (see docker's output above)"
      OFFICE_MODE=host
      ;;
    bridge)
      office_engine_run -p "$OFFICE_PPORT:80" ||
        die "engine failed to start on port $OFFICE_PPORT (see docker's output above)"
      OFFICE_MODE=bridge
      ;;
    auto)
      if office_engine_run -p "$OFFICE_PPORT:80"; then
        OFFICE_MODE=bridge
      else
        log "office: port publishing refused (nested container?) - retrying with --network host"
        docker rm -f fxcloud-office >/dev/null 2>&1 || true
        office_engine_run --network host ||
          die "engine failed to start with a published port and with the host network (see docker's output above). With --network host the engine needs port 80 - stop the local webserver occupying it first"
        OFFICE_MODE=host
      fi
      ;;
    esac
  else
    # existing container: make sure it runs, then learn how it is networked
    OFFICE_MODE=$(docker inspect -f '{{.HostConfig.NetworkMode}}' fxcloud-office)
    if [ "$(docker inspect -f '{{.State.Running}}' fxcloud-office)" != "true" ]; then
      log "office: starting the existing engine container"
      docker start fxcloud-office >/dev/null || die "the existing engine container failed to start"
    fi
  fi

  # local address for the readiness check, the proxy hint - and the loud
  # "where does it listen" line: this is the number your proxy needs
  if [ "$OFFICE_MODE" = host ]; then
    ENGINE_LOCAL_PORT=80
    log "office: engine runs in the host network - listens on port 80 of this host (proxy target: http://<this-host>:80)"
  else
    ENGINE_BIND=$(docker port fxcloud-office 80/tcp 2>/dev/null | head -n 1)
    ENGINE_LOCAL_PORT="${ENGINE_BIND##*:}"
    ENGINE_LOCAL_PORT="${ENGINE_LOCAL_PORT:-$OFFICE_PPORT}"
    log "office: engine published as ${ENGINE_BIND:-port $ENGINE_LOCAL_PORT} - proxy target: http://<this-host>:$ENGINE_LOCAL_PORT"
  fi

  # WOPI base: knob > existing unit > derived from how the engine reaches fxcloud
  OFFICE_WOPI="${FXCLOUD_OFFICE_WOPI_BASE:-}"
  if [ -z "$OFFICE_WOPI" ] && [ -f "$UNIT" ]; then
    OFFICE_WOPI=$(sed -n 's/^Environment=FXCLOUD_OFFICE_WOPI_BASE=//p' "$UNIT" | head -n 1)
  fi
  if [ -z "$OFFICE_WOPI" ]; then
    OFFICE_FX_PORT="${FXCLOUD_PORT:-}"
    if [ -z "$OFFICE_FX_PORT" ] && [ -f "$UNIT" ]; then
      OFFICE_FX_PORT=$(sed -n 's/^Environment=FXCLOUD_PORT=//p' "$UNIT" | head -n 1)
    fi
    OFFICE_FX_PORT="${OFFICE_FX_PORT:-8080}"
    if [ "$OFFICE_MODE" = host ]; then
      OFFICE_WOPI="http://127.0.0.1:$OFFICE_FX_PORT"
    else
      OFFICE_BIND="${FXCLOUD_BIND:-}"
      if [ -z "$OFFICE_BIND" ] && [ -f "$UNIT" ]; then
        OFFICE_BIND=$(sed -n 's/^Environment=FXCLOUD_BIND=//p' "$UNIT" | head -n 1)
      fi
      case "${OFFICE_BIND:-0.0.0.0}" in
      127.0.0.1 | localhost | ::1)
        die "fxcloud binds ${OFFICE_BIND} - the engine container cannot reach it. Set FXCLOUD_BIND=0.0.0.0 in $UNIT (systemctl restart fxcloud), or run the engine with FXCLOUD_OFFICE_NETWORK=host"
        ;;
      esac
      OFFICE_GW=$(docker network inspect "${OFFICE_MODE}" --format '{{(index .IPAM.Config 0).Gateway}}' 2>/dev/null || true)
      OFFICE_WOPI="http://${OFFICE_GW:-172.17.0.1}:$OFFICE_FX_PORT"
    fi
    log "office: WOPI base $OFFICE_WOPI"
  fi
fi

# ---- systemd --------------------------------------------------------------
if [ -f "$UNIT" ]; then
  log "keeping the existing $UNIT (only the binary was replaced)"
  if [ -n "$OFFICE_URL" ]; then
    # add only the office lines the unit is missing (rerun-proof): this is
    # how an already installed fxcloud gains office on a plain update
    OFFICE_ADD="$TMP/office-env"
    : > "$OFFICE_ADD"
    if ! grep -q '^Environment=FXCLOUD_OFFICE_URL=' "$UNIT"; then
      printf 'Environment=FXCLOUD_OFFICE_URL=%s\n' "$OFFICE_URL" >> "$OFFICE_ADD"
    fi
    if ! grep -q '^Environment=FXCLOUD_OFFICE_SECRET=' "$UNIT"; then
      printf 'Environment=FXCLOUD_OFFICE_SECRET=%s\n' "$OFFICE_SECRET" >> "$OFFICE_ADD"
    fi
    if ! grep -q '^Environment=FXCLOUD_OFFICE_WOPI_BASE=' "$UNIT"; then
      printf 'Environment=FXCLOUD_OFFICE_WOPI_BASE=%s\n' "$OFFICE_WOPI" >> "$OFFICE_ADD"
    fi
    if [ -n "${FXCLOUD_OFFICE_EMBED:-}" ] && ! grep -q '^Environment=FXCLOUD_OFFICE_EMBED=' "$UNIT"; then
      printf 'Environment=FXCLOUD_OFFICE_EMBED=%s\n' "$FXCLOUD_OFFICE_EMBED" >> "$OFFICE_ADD"
    fi
    if [ -s "$OFFICE_ADD" ]; then
      if grep -q '^\[Install\]' "$UNIT"; then
        log "office: adding FXCLOUD_OFFICE_* lines to $UNIT"
        awk -v insfile="$OFFICE_ADD" \
          '!done && /^\[Install\]/ { while ((getline l < insfile) > 0) print l; close(insfile); done = 1 } { print }' \
          "$UNIT" > "$UNIT.new" || die "cannot rewrite $UNIT"
        mv -f "$UNIT.new" "$UNIT" || die "cannot write $UNIT"
      else
        die "no [Install] section in $UNIT - add Environment=FXCLOUD_OFFICE_URL=... there by hand and re-run"
      fi
    fi
  fi
else
  log "writing $UNIT"
  cat > "$UNIT" <<EOF
[Unit]
Description=fxcloud - personal cloud (single-binary Nextcloud alternative)
After=network.target

[Service]
Type=simple
User=$USER_NAME
Group=$(id -gn "$USER_NAME")
WorkingDirectory=$HOME_DIR
ExecStart=$BIN
Restart=on-failure
RestartSec=3

# --- Environment configuration ---------------------------------------------
Environment=FXCLOUD_BIND=${FXCLOUD_BIND:-0.0.0.0}
Environment=FXCLOUD_PORT=${FXCLOUD_PORT:-8080}
Environment=FXCLOUD_DATA=$DATA_DIR
Environment=RUST_LOG=${RUST_LOG:-fxcloud=info}
EOF
  # Only knobs that carry a value get a line: an empty Environment= entry
  # would override the built-in default with "" and break the server.
  if [ -n "${FXCLOUD_ORIGIN:-}" ]; then
    printf 'Environment=FXCLOUD_ORIGIN=%s\n' "$FXCLOUD_ORIGIN" >> "$UNIT"
  else
    printf '# Environment=FXCLOUD_ORIGIN=https://cloud.example.com  # passkeys behind a proxy\n' >> "$UNIT"
  fi
  if [ -n "${FXCLOUD_SECURE_COOKIE:-}" ]; then
    printf 'Environment=FXCLOUD_SECURE_COOKIE=%s\n' "$FXCLOUD_SECURE_COOKIE" >> "$UNIT"
  else
    printf '# Environment=FXCLOUD_SECURE_COOKIE=1  # enable behind HTTPS\n' >> "$UNIT"
  fi
  if [ -n "${FXCLOUD_MAX_UPLOAD_MB:-}" ]; then
    printf 'Environment=FXCLOUD_MAX_UPLOAD_MB=%s\n' "$FXCLOUD_MAX_UPLOAD_MB" >> "$UNIT"
  fi
  if [ -n "${FXCLOUD_TRASH_DAYS:-}" ]; then
    printf 'Environment=FXCLOUD_TRASH_DAYS=%s\n' "$FXCLOUD_TRASH_DAYS" >> "$UNIT"
  fi
  if [ -n "${FXCLOUD_SESSION_TTL:-}" ]; then
    printf 'Environment=FXCLOUD_SESSION_TTL=%s\n' "$FXCLOUD_SESSION_TTL" >> "$UNIT"
  fi
  if [ -n "$OFFICE_URL" ]; then
    printf 'Environment=FXCLOUD_OFFICE_URL=%s\n' "$OFFICE_URL" >> "$UNIT"
    printf 'Environment=FXCLOUD_OFFICE_SECRET=%s\n' "$OFFICE_SECRET" >> "$UNIT"
    printf 'Environment=FXCLOUD_OFFICE_WOPI_BASE=%s\n' "$OFFICE_WOPI" >> "$UNIT"
    if [ -n "${FXCLOUD_OFFICE_EMBED:-}" ]; then
      printf 'Environment=FXCLOUD_OFFICE_EMBED=%s\n' "$FXCLOUD_OFFICE_EMBED" >> "$UNIT"
    fi
  fi
  cat >> "$UNIT" <<EOF

# --- Security hardening ----------------------------------------------------
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
# The binary and the data directory live in the service user's own home,
# so hiding /home would break the unit; the home directory is 750 and
# owned by the service user, which is the actual access control here.
ProtectHome=false
ReadWritePaths=$DATA_DIR
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true

[Install]
WantedBy=multi-user.target
EOF
fi
systemctl daemon-reload
systemctl enable fxcloud >/dev/null 2>&1 || true
systemctl restart fxcloud

# ---- wait for it ----------------------------------------------------------
# The port the service really uses: the knob, else what the unit says.
PORT="${FXCLOUD_PORT:-}"
if [ -z "$PORT" ] && [ -f "$UNIT" ]; then
  PORT=$(sed -n 's/^Environment=FXCLOUD_PORT=//p' "$UNIT" | head -n 1)
fi
PORT="${PORT:-8080}"
log "waiting for fxcloud on port $PORT"
i=0
until curl -fsS "http://127.0.0.1:$PORT/login" >/dev/null 2>&1; do
  i=$((i + 1))
  if [ "$i" -gt 20 ]; then
    systemctl status fxcloud --no-pager || true
    journalctl -u fxcloud -n 20 --no-pager || true
    die "the service did not come up"
  fi
  sleep 1
done

printf '\n'
log "$NEW is running"
printf '    open:      http://<this-host>:%s/ - the first account becomes the admin\n' "$PORT"
printf '    service:   systemctl status fxcloud\n'
printf '    data:      %s\n' "$DATA_DIR"
printf '    configure: edit %s, then systemctl restart fxcloud\n' "$UNIT"
if [ -n "$OFFICE_URL" ]; then
  printf '    office:    %s\n' "$OFFICE_URL"
  printf '    engine:    %s (%s network, local port %s)\n' "$OFFICE_IMAGE" "$OFFICE_MODE" "$ENGINE_LOCAL_PORT"
  printf '    proxy:     route %s to http://<this-host>:%s\n' "$OFFICE_URL" "$ENGINE_LOCAL_PORT"
  printf '               (local proxy: http://127.0.0.1:%s; websocket upgrade + TLS - INSTALL.md)\n' "$ENGINE_LOCAL_PORT"
  printf '    branding:  %s/welcome - links to %s\n' "$OFFICE_DIR" "$OFFICE_LINK"
  if [ "$OFFICE_LINK" = "/" ] &&
    grep -qF 'href="/"' "$OFFICE_DIR/welcome/docker.html" 2>/dev/null; then
    printf '    note:      the landing page button points at "/" - set a valid FXCLOUD_ORIGIN\n'
    printf '               in %s and re-run this script to point it at your cloud\n' "$UNIT"
  fi
fi
if [ -f "$BIN.bak" ]; then
  printf '    rollback:  systemctl stop fxcloud && cp %s %s && systemctl start fxcloud\n' "$BIN.bak" "$BIN"
fi
# An upgraded unit can predate a knob: the update keeps the unit (on
# purpose), so point at what passkeys behind a proxy would now need.
if ! grep -q '^Environment=FXCLOUD_ORIGIN=' "$UNIT"; then
  printf '    note:      this unit sets no FXCLOUD_ORIGIN - behind a reverse proxy, passkeys\n'
  printf '               need it: add Environment=FXCLOUD_ORIGIN=https://<public-url> and\n'
  printf '               FXCLOUD_SECURE_COOKIE=1 to %s, then systemctl restart fxcloud\n' "$UNIT"
fi

# ---- office engine readiness (last, everything else is already up) -------
# nginx answers within seconds, the document service (and its font cache on
# first start) takes longer;502/503 mean "still booting", no answer at all
# means the engine is not reachable locally.
if [ -n "$OFFICE_URL" ]; then
  ENGINE_DEEP="http://127.0.0.1:$ENGINE_LOCAL_PORT/hosting/wopi/odt/edit?wopisrc=x&access_token=bogus"
  log "office: waiting for the editor engine (first start generates the font cache)"
  i=0
  while :; do
    CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$ENGINE_DEEP" 2>/dev/null || true)
    case "$CODE" in
    502 | 503 | 000) ;;
    *) break ;;
    esac
    i=$((i + 1))
    if [ "$i" -gt 180 ]; then
      docker logs --tail 30 fxcloud-office >&2 || true
      die "fxcloud is up, but the office engine is not ready after 180s - see the docker log above (docker logs fxcloud-office)"
    fi
    if [ $((i % 30)) -eq 0 ]; then
      log "office: still waiting for the editor engine ($i s)"
    fi
    sleep 1
  done
  # apply a landing-page conf we extended to a kept engine (a container
  # created in this run already read it at start)
  if [ "$OFFICE_CONF_CHANGED" = 1 ] && [ "$OFFICE_RECREATE" = 0 ]; then
    if docker exec fxcloud-office nginx -t >/dev/null 2>&1 &&
      docker exec fxcloud-office nginx -s reload >/dev/null 2>&1; then
      log "office: engine reloaded - the landing page is no longer cached for a year"
      # prove the reload took effect: the conf is a FILE bind mount, a
      # rename-save editor decouples it and every write stays invisible
      WCODE=000
      i=0
      while [ "$i" -lt 10 ]; do
        WCODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
          "http://127.0.0.1:$ENGINE_LOCAL_PORT/welcome/" 2>/dev/null || true)
        if [ "$WCODE" = 200 ]; then break; fi
        i=$((i + 1))
        sleep 1
      done
      if [ "$WCODE" != 200 ]; then
        log "office: /welcome/ still answers $WCODE - restarting the engine so it picks up ds-branding.conf (in-flight editor sessions drop)"
        docker restart fxcloud-office >/dev/null || true
        i=0
        while [ "$i" -lt 30 ]; do
          WCODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 \
            "http://127.0.0.1:$ENGINE_LOCAL_PORT/welcome/" 2>/dev/null || true)
          if [ "$WCODE" = 200 ]; then break; fi
          i=$((i + 1))
          sleep 1
        done
        if [ "$WCODE" = 200 ]; then
          log "office: landing page OK after the restart"
          # the restart also dropped the document service - wait for it again
          i=0
          while [ "$i" -lt 30 ]; do
            CODE=$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$ENGINE_DEEP" 2>/dev/null || true)
            if [ "$CODE" != 502 ] && [ "$CODE" != 503 ] && [ "$CODE" != 000 ]; then break; fi
            i=$((i + 1))
            sleep 1
          done
        else
          log "office: /welcome/ still answers $WCODE - compare what nginx sees: docker exec fxcloud-office cat /etc/nginx/includes/ds-branding.conf"
        fi
      fi
    else
      log "office: could not reload the engine nginx - run: docker exec fxcloud-office nginx -s reload"
    fi
  fi
  log "office: editor engine ready"
fi
