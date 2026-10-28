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
#
# Knobs (environment variables in front of the command, all optional):
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
#   FXCLOUD_SESSION_TTL    session lifetime in seconds (default: 2592000)
#   RUST_LOG               log filter (default: fxcloud=info)
#
# The knobs configure the unit on a fresh install only; afterwards edit
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

# ---- systemd --------------------------------------------------------------
if [ -f "$UNIT" ]; then
  log "keeping the existing $UNIT (only the binary was replaced)"
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
