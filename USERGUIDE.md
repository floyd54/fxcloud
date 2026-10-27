# fxcloud User Guide

This guide is for people who *use* an fxcloud instance: how to sign up,
work with your files, share them, encrypt them and sign in with a passkey.
It also walks an administrator through the one deployment step passkeys
care about (HTTPS behind a reverse proxy with `FXCLOUD_ORIGIN`).

Developer-facing documents:

- [README.md](README.md) - install, configuration table, systemd unit
- [API.md](API.md) - HTTP endpoints and protocol details
- [ENCRYPTION.md](ENCRYPTION.md) - the cryptographic design in full
- [ARCHITECTURE.md](ARCHITECTURE.md) - code layout, storage, quotas

## Contents

1. [Install](#1-install)
2. [The first account](#2-the-first-account)
3. [Signing in](#3-signing-in)
4. [Your files](#4-your-files)
5. [Sharing](#5-sharing)
6. [Trash](#6-trash)
7. [Quotas](#7-quotas)
8. [User administration](#8-user-administration)
9. [Your account settings](#9-your-account-settings)
10. [Encryption](#10-encryption)
11. [Passkeys](#11-passkeys)
12. [HTTPS behind a reverse proxy (worked example)](#12-https-behind-a-reverse-proxy-worked-example)
13. [WebDAV](#13-webdav)
14. [Troubleshooting](#14-troubleshooting)

## 1. Install

fxcloud is a single binary: SQLite and the web interface are built in, there
is no database server and no runtime dependency.

**Prebuilt binary** - every tagged release on [GitHub
Releases](https://github.com/floyd54/fxcloud/releases) ships a fully static
Linux x86_64 build (~6 MB):

```bash
chmod +x fxcloud-<tag>-x86_64-unknown-linux-musl
FXCLOUD_DATA=/srv/fxcloud ./fxcloud-<tag>-x86_64-unknown-linux-musl
```

**From source**:

```bash
cargo build --release
./target/release/fxcloud      # creates ./data with the DB and file blobs
```

Open <http://127.0.0.1:8080>. To run it as a service on Linux, use the
hardened unit from [`deploy/fxcloud.service`](deploy/fxcloud.service) -
the [README](README.md#deployment) has the step-by-step. All settings are
environment variables (bind address, port, data directory, quota-related
limits, ...); the full table is in
[README.md](README.md#configuration).

## 2. The first account

On a fresh instance, open the **Create account** tab, pick a username (3
characters or more), an optional display name and a password (8 characters
or more).

The **first account** created on an instance is activated immediately and
becomes its administrator. Every account created after that starts
inactive: registration succeeds, but sign-in is refused with a hint to
contact the administrator until an active account activates it (see
[User administration](#8-user-administration)).

## 3. Signing in

The sign-in page has three tabs:

- **Sign in** - username and password.
- **Passkey** - username only; the device then asks for a PIN or
  biometrics (see [Passkeys](#11-passkeys)).
- **Create account** - registration, as above.

Sessions last 30 days by default (`FXCLOUD_SESSION_TTL`).

## 4. Your files

The file explorer works like a desktop file manager, in the browser:

- **New file** / **New folder** create entries in the current folder; a new
  text file opens straight in the built-in editor (with a Markdown preview
  toggle and **Save**).
- **Upload file** / **Upload folder**, or drag & drop onto the drop zone,
  upload files or whole folder trees (empty subfolders included).
- **Show hidden** toggles entries whose name starts with a dot; the choice
  is remembered in your browser.
- Click a file to preview it: images, video, audio, PDF, HTML and text
  open in a lightbox; text files open in the editor.
- Selection checkboxes (Shift+click extends over a range) give you the
  bulk bar: **Download** (the whole selection as one ZIP), **Move to...**,
  **Copy to...**, **Share**, **Delete** and **Clear**.
- Every row also has a menu (Download, Share, Move, Copy, Rename, Delete).
- Folder rows show their recursive size; the breadcrumb walks you down the
  tree.

ZIP downloads are assembled per request and capped at 1 GiB uncompressed;
take fewer items if the error tells you to.

## 5. Sharing

Share files or folders with other accounts of the same instance:

1. Select one or more items and press **Share**.
2. Pick the user from the dropdown.
3. Tick the permissions to grant: **Read**, **Write**, **Create**,
   **Delete** (a fifth box, Share, is reserved for re-sharing and has no
   effect yet).
4. Press **Share**.

A share appears in the other person's root file tree, marked with your
name; if the name is taken there, it gets a suffix
(`Projekte` becomes `Projekte (alice) 2`). Everything they create inside a
shared folder lands in *your* tree and counts against *your* quota.

To revoke, open the **Share** dialog for the item again and press
**Remove** next to the person.

When [encryption](#10-encryption) is on for both sides, the share also
carries a key envelope sealed to the other person's public key - their
key fingerprint is shown in the dialog so you can compare it out of band
before trusting the exchange.

## 6. Trash

Nothing is deleted immediately: **Delete** moves entries to your personal
trash, where they can be **Restore**d or **Delete permanently**.
**Empty trash** clears everything at once.

A background sweep removes trashed entries for good after 30 days
(`FXCLOUD_TRASH_DAYS`); the trash list shows each entry's deadline, and
trashed content still counts against your quota while it sits there.

## 7. Quotas

Every account has a storage quota - 1 GiB by default, set per account by
an administrator. What counts is everything *you own*: files you uploaded,
copies you made, and content others shared *to you* counts against the
original owner. Exceeding it yields a clear `507 Insufficient Storage`
error in the web UI and in WebDAV; your current usage is shown in
**Settings** ("Storage: used of quota").

## 8. User administration

Administrators get a **User administration** entry in the menu behind
their name in the top bar. There they can:

- **activate / deactivate** accounts (takes effect instantly: sessions and
  WebDAV included; an administrator cannot deactivate themselves),
- **grant / revoke the administrator role** (the last active administrator
  can neither be deactivated nor demoted),
- **set the storage quota** per account,
- **reset a password**, which hands back a one-time generated temporary
  password for the user's next sign-in.

Deactivated accounts can neither sign in nor use WebDAV and get a 403
with a hint to contact the administrator. Display name, theme and password
are *not* on this list: every user changes those themselves in
**Settings**.

## 9. Your account settings

The menu behind your name in the top bar opens **Settings**:

- **Account** - username, member since, storage used of quota.
- **Display name** - changeable by you, shown to other users.
- **Theme** - Light or Dark.
- **Password** - change it; the current password is asked first.
- **Passkeys** - manage your sign-in devices (see below).

## 10. Encryption

fxcloud can encrypt files **in your browser** before they leave your
device: the server stores ciphertext and a wrapped key, and can still see
file names, sizes and sharing - those are what the storage service needs.
The full design (threat model, key hierarchy, the DECISIONs) lives in
[ENCRYPTION.md](ENCRYPTION.md); this is the user's view:

- The badge in the top bar shows the state: **Encrypt uploads** (not set
  up yet), **Unencrypted**, or **Encrypted**.
- Turning it on, you choose between **Use my fxcloud login password**
  (the default) and **Choose a separate passphrase**.
- You are then shown a **recovery key** (64 hex digits). Save it: it is
  the only way back into your files if the passphrase is forgotten.
- The keys live in the current tab's memory only - a reload puts you back
  to **Unencrypted**, and the unlock pane asks for the passphrase again.
- With encryption on, uploads are encrypted, downloads and previews are
  decrypted in the browser, and sharing carries the key envelope described
  above. WebDAV desktop clients do not encrypt: encrypted files are
  visible there as ciphertext and cannot be written through them.

## 11. Passkeys

A passkey signs you in with a PIN or biometrics instead of a password.
fxcloud uses username-first FIDO2/WebAuthn with ES256 and requires user
verification (a PIN or biometric gesture, not just a touch).

**Add one:** open **Settings**, **Passkeys**, press **Add passkey**, give
it a name (e.g. "phone", "security key") and confirm with your device.
The list shows your devices with their last use; each can be **Rename**d
or **Remove**d. Removing the last one is allowed - your password keeps
working, and a lost device can be cut off immediately.

**Sign in:** switch to the **Passkey** tab on the sign-in page, enter your
username, and confirm with the device's PIN or biometrics. An unknown
username and an account without passkeys get the same answer, so the
dialog does not reveal who has an account.

Requirements:

- A **secure context**: browsers only expose passkeys over HTTPS or on
  `localhost`. Over plain HTTP on a LAN address the UI tells you the
  browser blocks them.
- The passkey is bound to the origin and hostname it was created under.
  If your instance is served under a URL, that URL must be announced to
  fxcloud with `FXCLOUD_ORIGIN` - the next section shows how, and what
  the error looks like when it is missing.

## 12. HTTPS behind a reverse proxy (worked example)

fxcloud speaks plain HTTP, so a reverse proxy terminates TLS in front of
it. Passkeys are the reason this needs one extra setting: WebAuthn binds
every passkey to the exact `scheme://host[:port]` it was created under,
and the browser sends its `Origin` on every passkey request. fxcloud
compares that header with the origin it derives from the forwarded
scheme and `Host` - and, behind a proxy that rewrites `Host` or does not
forward the scheme, the two disagree.

The symptom is this error, when adding or using a passkey:

```
bad request: Origin does not match this server's address - set
FXCLOUD_ORIGIN to the URL users open it under
```

The fix is one environment variable: tell fxcloud the URL users actually
open it under. Worked example with nginx on `cloud.example.com` and
fxcloud on the same host, port 8080:

**1. fxcloud** (systemd unit, or the shell for a quick test):

```bash
FXCLOUD_BIND=127.0.0.1 FXCLOUD_PORT=8080 \
FXCLOUD_SECURE_COOKIE=1 \
FXCLOUD_ORIGIN=https://cloud.example.com \
./fxcloud
```

In the provided unit file (`deploy/fxcloud.service`) the same two lines,
commented, wait in the environment section:

```ini
# Enable when serving over HTTPS behind a TLS-terminating reverse proxy:
# Environment=FXCLOUD_SECURE_COOKIE=1
# The exact URL users open fxcloud under - required for passkeys when a
# reverse proxy rewrites Host or terminates TLS (e.g. https://cloud.example.com):
# Environment=FXCLOUD_ORIGIN=https://cloud.example.com
```

**2. nginx** terminates TLS and forwards to it:

```nginx
server {
    listen 443 ssl;
    server_name cloud.example.com;

    client_max_body_size 10G;   # keep in sync with FXCLOUD_MAX_UPLOAD_MB

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Real-IP         $remote_addr;
        proxy_set_header X-Forwarded-For   $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_request_buffering off;
        proxy_buffering off;
    }
}
```

**3. Restart fxcloud** (after changing the unit:
`sudo systemctl daemon-reload && sudo systemctl restart fxcloud`).

Rules for the value of `FXCLOUD_ORIGIN`:

- It must equal what the browser's address bar shows as origin: scheme,
  host, and port if it is not the scheme's default (443 for https, 80
  for http) - and **no trailing slash**, no path.
- If users reach the instance under several names, passkeys work under
  the one configured here; pick the canonical URL.
- It only affects WebAuthn. Everything else keeps working with the proxy
  headers from the nginx block above, and setting it is harmless when no
  proxy is involved.

Without `FXCLOUD_ORIGIN`, fxcloud derives the origin per request from
`X-Forwarded-Proto` (or `FXCLOUD_SECURE_COOKIE`) plus `Host`, which is
correct when the proxy passes both through unchanged - and wrong the
moment it does not.

## 13. WebDAV

fxcloud speaks WebDAV at **`/dav/`** with HTTP Basic auth (your fxcloud
username + password; passkeys are web-only). The path after `/dav/` is
relative to your home folder:

```bash
rclone config    # type: webdav, url: https://your-host/dav/, user/pass
rclone lsd remote:

# Windows "Map network drive" / macOS Finder "Connect to Server" -> /dav/
```

Deactivated accounts get 403, quota violations 507. Encrypted files show
up as ciphertext and cannot be written from a desktop client (see
[Encryption](#10-encryption)); the web UI is the way in and out for those.

## 14. Troubleshooting

**"Origin does not match this server's address - set FXCLOUD_ORIGIN ..."**
when adding or using a passkey: the URL users open fxcloud under differs
from what fxcloud derives from the proxy headers. Set `FXCLOUD_ORIGIN` as
in [section 12](#12-https-behind-a-reverse-proxy-worked-example) and
restart.

**The passkey UI says the browser blocks passkeys**: you are on plain
HTTP (or an IP address) rather than HTTPS or localhost - browsers only
expose passkeys in a secure context. Serve fxcloud over HTTPS.

**"Account created. It has to be activated before you can sign in"**:
expected for every account after the first - an administrator activates
it in **User administration**.

**"account is not activated yet - ask an administrator to activate it"**
at sign-in or over WebDAV: same cause, now on an existing account.

**507 "storage quota exceeded: X of Y used"**: your quota is full -
empty the trash (it keeps counting), delete files, or ask an
administrator to raise the quota.

**Encrypted files do not open**: the storage passphrase is not unlocked
in this tab (the keys live in tab memory only) - use the unlock pane; if
the passphrase is forgotten, the recovery key from setup recovers it.

**Sync client writes fail on encrypted files**: desktop clients do not
encrypt; WebDAV serves those files as ciphertext, read-only. Use the web
UI for encrypted content.
