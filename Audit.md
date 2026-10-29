# Security audit of fxcloud

Date: 2026-10-28 (state of `main` at v0.0.28, tag `v0.0.28`)

Scope: the whole repository - the Rust server (9.2 klines), the frontend
(7.7 klines), the installer, the Dockerfile and the CI workflows.

Method: manual review of every authentication, authorization, cryptographic
and file-handling code path in this repository, plus an automated
dependency scan (`cargo audit`, RustSec advisory database: **0
vulnerabilities across 211 crate dependencies**). The integration suite
(539 checks) and the unit tests (41) were green at the time of review.

This document is a living record. Findings carry an id, a severity and a
status; the status line moves as fixes land. Severity uses the usual
scale: High (directly exploitable for account or data compromise),
Medium (weakens the security posture, exploitable under realistic
conditions), Low (hardening / defense in depth), Info (accepted trade-off
or operator note).

## Threat model (what this server defends against)

fxcloud is a personal cloud, usually reachable through a reverse proxy
on the public internet. The attacker model assumes:

* unauthenticated internet traffic can reach every public route;
* a legitimate user's browser, session token or password may be stolen;
* the server host, its database and its blobs may at some point be read
  by someone who is not the account owner (this is what the client-side
  encryption defends - ENCRYPTION.md section 5);
* shares are a trust boundary: a grantee is a semi-trusted party who
  must not exceed the permission bits they were given.

Out of scope: a compromised server *process* while keys are unlocked in
a browser tab, physical access to an unlocked workstation, and
side-channel attacks against WebCrypto/Argon2 implementations.

## Findings at a glance

| id | area | severity | status |
|----|------|----------|--------|
| F1 | no rate limiting / lockout on the authentication endpoints | Medium | fixed in v0.0.32 |
| F2 | no security headers on the UI (CSP, clickjacking, HSTS, nosniff) | Medium | fixed in v0.0.29 |
| F3 | password change and admin reset keep existing sessions alive | Medium | fixed in v0.0.31 |
| F4 | sessions are long-lived (30 days) with no rotation or management UI | Medium | fixed in v0.0.33 |
| F5 | a share UPDATE-grantee can replace an existing file/folder key record | Low-Med | fixed in v0.0.30 |
| F6 | `covering_share` walks parents without a depth cap | Low | open |
| F7 | the installer does not verify a checksum of the downloaded binary | Low | fixed (installer + CI) |
| F8 | without `FXCLOUD_ORIGIN` the WebAuthn origin follows the Host header | Low | open |
| F9 | no connection/request rate limits beyond the body cap | Info | accepted |
| F10 | login timing differs for unknown usernames (fast 401) | Info | open |
| F11 | registration answers "username already taken" (enumeration) | Info | accepted |
| F12 | SQLite `synchronous = NORMAL`: power loss may cost recent writes | Info | accepted |
| F13 | login password crosses one redirect via sessionStorage | Info | accepted |
| F14 | Basic-auth verdict cache is keyed by a non-cryptographic hash | Info | accepted |

## Findings in detail

### F1 - No rate limiting or lockout on the authentication endpoints (Medium) - fixed in v0.0.32

*Fixed.* Every authentication door now spends from in-memory counters
(`AppState::auth`, pruned on every use the way the ceremonies map
prunes). A per-account failure count with exponential backoff refuses
the sixth consecutive wrong password with 429 and `Retry-After` (five
failures buy a 10-second window, each further one doubles it up to a
300-second cap), and the refusal answers *before* the database or
Argon2 see the request - the right password waits out the window too,
so a locked name costs the server nothing to refuse. The counter is
keyed by the name itself, existing or not, and unknown names lock
identically, so the 429 cannot be used to distinguish an account holder
from an invented name; a successful sign-in clears it. Two
source-address budgets bound what one socket peer can trigger: 30 failed
sign-ins per minute and 10 registrations per ten minutes, each refused
with 429 + `Retry-After`, the register budget *before* its Argon2 hash
runs (a taken name pays for it all the same). The key is the socket
peer only - `X-Forwarded-For` is deliberately never trusted, because a
bare install would be one spoofed header away from a limiter that both
misses the attacker and can be aimed at another user; behind a reverse
proxy the budgets therefore describe the proxy's address, where they
are set generously on purpose and the per-account backoff stays the
precise instrument. `AppState::ceremonies` is capped at 256 pending
challenges (429 beyond it) with 5 seconds in `Retry-After`, which
closes the uncapped-growth half of the report. The UI translates
`rate_limited` with the `retry_after` seconds that ride in the body
beside the header. Twelve suite pins cover the sixth-attempt 429 with
header/body agreement, the right password waiting too, recovery and
counter clearing after the window, the unknown-name and passkey-door
uniformity, and all three budgets tripping to 429.

The original report follows, kept for the record.

`POST /api/login`, `POST /api/register` and the two public passkey
endpoints (`/api/passkeys/login/start`, `/finish`) accept unlimited
attempts. There is no per-IP or per-account counter anywhere in
`src/`.

*Impact.* Password guessing is throttled only by the server-side
Argon2id cost (~180 ms and 64 MiB per verification), which caps a single
core at roughly five attempts per second - millions per day on a
dedicated attacker, and each attempt is a *cheap-to-trigger* expensive
operation, so a flood also doubles as CPU/RAM exhaustion (the DB pool
runs eight connections; each login occupies one for the duration of the
hash). The passkey endpoints cost almost nothing server-side, so
ceremony spam is purely a resource question (`AppState::ceremonies`
grows with requests inside the 5-minute TTL window; it is pruned on
insert, but not capped).

*Recommendation.* A small in-memory token bucket per source IP and per
username (the `ceremonies` map already shows the pattern), a failed-
attempt counter per account with exponential backoff, and `Retry-After`
on the 429. The suite can pin the behaviour the way it pins the
origin-refusal warnings.

### F2 - No security headers on the UI (Medium) - fixed in v0.0.29

*Fixed.* A `security_headers` middleware in `src/web/mod.rs` now attaches
`nosniff`, `X-Frame-Options: SAMEORIGIN`, `Referrer-Policy: same-origin`
and a strict CSP to every response, only when the route has not set the
header itself (the preview route keeps its stronger `sandbox` CSP, the
download route keeps its own `nosniff`). `SAMEORIGIN` rather than `DENY`
because the app embeds its own previews in an iframe. The CSP allows
`'wasm-unsafe-eval'` in `script-src` because the client-side Argon2id
compiles WebAssembly (`hashwasm-argon2.js`); `img-src`/`media-src`/
`frame-src` carry `blob:` for the decrypt-and-blob preview flow and
`https:` so Markdown previews may reference external images. HSTS
(`max-age=15552000`) rides along when `FXCLOUD_SECURE_COOKIE` is set, so
plain-HTTP installs are unaffected. Eleven suite pins cover the header
set, the CSP directives, the never-overwrite rule and both HSTS modes.

The original report follows, kept for the record.

`src/web/ui.rs::serve_asset` sends only `Content-Type` and
`Cache-Control`. The HTML pages carry no CSP, no clickjacking
protection, no `Referrer-Policy`; only `/api/files/download` and
`/api/files/preview` set `X-Content-Type-Options: nosniff` (and the
preview sets `Content-Security-Policy: sandbox`).

*Impact.* The app itself is currently XSS-clean (see "What is already
solid"), so this is not a hole today - it is the missing safety net.
A single future `innerHTML` mistake would execute with no CSP to blunt
it, and today any page can iframe the login form (`frame-ancestors` is
unrestricted), which is a clickjacking nuisance at minimum.

*Recommendation.* One tower layer for every response:

    X-Content-Type-Options: nosniff
    X-Frame-Options: DENY
    Referrer-Policy: same-origin
    Content-Security-Policy: default-src 'self'; script-src 'self';
      style-src 'self' 'unsafe-inline'; img-src 'self' data: blob:;
      media-src 'self' blob:; frame-src 'self' blob:;
      frame-ancestors 'none'; base-uri 'self'; object-src 'none'

(`style-src` needs `'unsafe-inline'` because the HTML carries static
`style=` attributes and JS sets element styles; `img-src`/`media-src`/
`frame-src` need `blob:` for the decrypt-and-blob preview flow and the
sandboxed HTML/PDF preview frame.) Add `Strict-Transport-Security`
when `secure_cookie` is on. The `sandbox` header on preview responses
stays as is. Neither HTML page contains an inline script, so
`script-src 'self'` holds without exceptions.

### F3 - Password change and admin reset keep existing sessions alive (Medium) - fixed in v0.0.31

*Fixed.* `Db::set_password` now takes the caller's own session token as
`keep_session` and deletes every *other* session of that account in the
same statement batch as the hash update, so a password change ends the
sessions the old password minted. `change_password` passes the token it
reads from its own request's cookie header (`AuthUser` resolves it but
carries only the user, not the string); the admin reset passes `None`,
dropping every session of the target - a reset is called for precisely
when an account may be compromised. The caller's own session staying
open is the one deliberate carry-over: it authenticated this very
request, so the menu that made the change keeps working, and the UI now
says so ("Other sessions of this account were signed out"). Seven suite
pins cover the second sign-in being cut off by a self-service change
while the caller's survives, the reset dropping both standing sessions
of the target, and the administrator's own session surviving it.

The original report follows, kept for the record.

`PUT /api/me/password` (`routes/auth.rs::change_password`) and the
admin reset (`routes/admin.rs::reset_password`) both call
`Db::set_password`, which updates the hash and nothing else. The
comment in `db/user.rs` documents this as deliberate ("every other tab
of this account keeps working"), and the admin path even calls it out.

*Impact.* The classic stolen-credential scenario is not closed: an
attacker with a stolen session cookie keeps access after the victim
notices, changes the password and believes the incident is over - for
up to `FXCLOUD_SESSION_TTL` (default 30 days). The same holds for an
administrator resetting a reported-compromised account.

*Recommendation.* `DELETE FROM sessions WHERE user_id = ?` on both
paths. For the self-service change the caller's own session can be kept
(its token is already authenticated for this request); for the admin
reset, dropping every session of the target is the expected behaviour.

### F4 - Long-lived sessions: 30-day default, no rotation, no management (Medium) - fixed in v0.0.33

Tokens are 32 bytes from `OsRng` (good), stored until their expiry
(good), purged hourly (good) - but the default TTL is 30 days, a token
never rotates while in use, and neither the UI nor the API offers a way
to see or end other sessions.

*Impact.* Any token leak (XSS in a third-party browser extension, a
proxy log, a copied cookie jar) stays valid for weeks. There is no
"sign out everywhere" button for the incident case.

*Recommendation.* Shorter default TTL (7 days) with sliding renewal on
authenticated requests, plus a `GET /api/me/sessions` /
`DELETE /api/me/sessions` pair and a settings entry listing the current
sessions.

*Fixed (v0.0.33).* The default window is now **7 days** (604800 s,
still `FXCLOUD_SESSION_TTL`-overridable) and a session in use slides:
every API request carrying a session cookie passes a renewal middleware
whose write sits behind a `WHERE last_seen_at < cutoff` - a quarter of
the lifetime, capped at a day - so a session within its window costs
one indexed statement that matches no row, and one that is due moves
exactly once per window. A failed renewal is logged and otherwise
ignored; it never fails the request. Renewal deliberately does **not**
rotate the token *value*: a second tab holding the old value would get
a 401 mid-renewal and bounce its user to the login page, and the leak
the rotation would address is answered by the other half of the fix -
the victim can now see the unknown device and end it. (Every sign-in
already mints a fresh token, and F3 still ends the sibling sessions on
a password change.) The management side is a new settings section: the
listing shows each live session with its device (User-Agent, captured
at sign-in, capped at 200 characters), created / last-used / expiry
dates, and marks the row belonging to the current cookie; every other
row can be ended right there, and one button ends *every* other
session - the incident case the finding describes. The API surface is
`GET /api/me/sessions`, `DELETE /api/me/sessions` (ends all but the
caller's own, answers `{ended: n}`) and `DELETE /api/me/sessions/{sid}`
(204). A session's primary key IS the secret token, so the listing
never exposes it: it shows `sid`, a 16-byte public handle written by
migration 013, and every query using a sid is scoped to the caller's
own `user_id` - a sid is a label, not a key, and another account's sid
answers 404 like every stranger's id. Alt-DBs gain `sid` (random),
`user_agent` ('' for old rows, which show no device line) and
`last_seen_at` (= `created_at`) through the same migration. Fifteen
suite pins cover the listing shape (multiple sessions, exactly one
current, no token field), the 604800-second default measured with
`julianday`, a per-device end that really kills the victim's cookie
while the current session lives, the foreign-sid 404, the incident
button (ends N, leaves exactly the caller), sliding renewal (a
backdated `last_seen_at` moves on the next call and rewrites the
window to exactly 7 days from the touch), the one-write-per-window
property, and the UI / i18n / migration wiring.

### F5 - A share UPDATE-grantee can replace an existing key record (Low-Medium) - fixed in v0.0.30

*Fixed.* `Db::set_enc_key` now draws the line `save_content` draws on
its key field, in the same words: a record that exists may only be
replaced by the row's owner (`user_id == tree_owner`), refused with the
same `ForbiddenDetail` message. A row with *no* record may still be
given one by anyone holding UPDATE - the first encrypted write below a
folder, the documented purpose of this door, where nothing is keyed
under the old record yet and so nothing a swapped-in key could orphan.
The wrapper stays opaque to the server, which is exactly why the rule
is a narrower door rather than a check: there is no condition on which
a grantee's replacement is verifiably benign, so there is no exception
to grant. The cost is stated openly: an UPDATE-grantee can no longer
re-bind a moved encrypted row inside a share (the server would refuse
it), so the frontend refuses that transfer up front - before the
re-bind half-runs - naming the reason in a new string in all three
dictionaries, and the row stays where it was rather than arriving
unopenable. The owner moves it instead. Four suite pins cover the
grantee's first record, the grantee's refused replacement (message and
stored bytes untouched), and the owner's unchanged ability to replace.

The original report follows, kept for the record.

`PUT /api/files/key` (`routes/files::put_key` -> `Db::set_enc_key`)
authorizes with `PERM_UPDATE` via `update_target` and then writes
`enc_key` unconditionally. The *content* endpoint applies a stricter
rule for exactly this situation ("only the row's owner may change its
key record", `routes/files.rs::save_content`), but the key endpoint
does not.

*Impact.* A grantee with UPDATE on a keyed file or folder can replace
the stored wrapper with one only they can unwrap. Confidentiality is
unaffected (the server never sees keys, and the owner's already-wrapped
file keys stay intact), but the owner loses the ability to unwrap
*future* writes in that tree - a persistent integrity/availability hit
that survives restarts and is invisible until the next encrypted save.

*Recommendation.* Mirror the `save_content` rule in `set_enc_key`: an
existing record may only be replaced by the row's owner; setting a
record where none exists (the first encrypted write below a folder, the
documented purpose of this door) stays available to UPDATE grantees.
The suite pins this the way it pins the content-side rule.

### F6 - `covering_share` walks parents without a depth cap (Low)

`db/share.rs::covering_share` climbs `parent_id` until it finds a
share. `under_trash` (the sibling walk in `db/file.rs`) caps the same
kind of walk at 64 hops and answers 404; `covering_share` has no cap.

*Impact.* Not reachable through the API - `move_entry` refuses cycles
explicitly (the guard at `db/file.rs` "new parent must not be the entry
itself or a descendant"). Only a corrupted database could produce a
parent cycle, and then the affected DB thread would spin forever
instead of failing. Robustness, not an exploit path.

*Recommendation.* Same 64-hop cap, returning "no share".

### F7 - The installer verifies the download only by ELF magic and `--version` (Low) - fixed (no binary change: installer + CI only)

`install.sh` checks that the download starts with `\x7fELF` and answers
`--version` under a timeout. The transport is TLS to GitHub; the asset
itself is not checksummed against anything the repository publishes.

*Impact.* A compromised release asset (GitHub account, CI token) would
be installed verbatim by every update. This is the standard `curl | sh`
risk; the finding is the missing *cheap* mitigation.

*Recommendation.* The release workflow already has the binary; have it
write a `SHA256SUMS` asset, and have the installer fetch and verify it
(only when present, so old releases keep installing). An optional
minisign/GPG signature is the stronger follow-up.

*Fixed (installer + CI, no binary change).* The release workflow now
writes a `SHA256SUMS` asset next to the binary - one line in the
standard `sha256sum` format - and `install.sh` fetches it right after
the download, before the ELF check, the exec probe or the install step
see the file: the asset's line is picked by name, the hash is computed
over the download and compared, and a mismatch - or a `SHA256SUMS` that
fails to mention the asset - ends the install with `die`. Absence
stays legal: releases tagged before v0.0.34 have no checksum file, a
host without `sha256sum` is noted, and both fall through to the
pre-existing ELF magic + `--version` checks, so no old tag ever becomes
uninstallable. The transport was already TLS to GitHub; this binds the
asset's bytes to what the repository's own workflow published - the
cheap mitigation the finding asks for (minisign/GPG stays the stronger
follow-up). Five suite pins cover the CI step, the installer's
verification and its optional-file fallback, plus a functional round
trip of the shared format: an intact file matches, a tampered one does
not.

### F8 - Without `FXCLOUD_ORIGIN` the WebAuthn origin follows the Host header (Low)

`webauthn.rs::origin_and_rp` derives scheme and authority from
`X-Forwarded-Proto`/`FXCLOUD_SECURE_COOKIE` and `Host` when
`FXCLOUD_ORIGIN` is unset, and the browser's `Origin` header must then
match. The refusal paths are journaled at WARN with the headers in
play (added in v0.0.26), and the installer prints a hint when an
upgraded unit lacks the knob.

*Impact.* A request without an `Origin` header (non-browser client)
skips that comparison - harmless, because forging a ceremony still
requires the authenticator's signature over the server-issued
challenge. The residual risk is a deployment behind a
Host-rewriting proxy where passkeys silently stop working, which is now
loud in the journal. Keeping the derivation is right for `http://`
dev-mode; the deployment requirement just deserves more emphasis.

*Recommendation.* Startup warning at WARN level when the bind address
is not loopback and `FXCLOUD_ORIGIN` is unset; README "Security" note
that a public deployment needs both HTTPS and the knob.

### F9 - No connection or request rate limits beyond the body cap (Info, accepted)

`DefaultBodyLimit` caps every body at `max_upload_bytes`; there is no
per-IP connection cap or global request throttle. For the intended
deployment (one household, a reverse proxy in front that can rate
limit) this is an accepted trade-off; the proxy is the documented
throttle. Revisit if fxcloud is ever exposed directly at scale.

### F10 - Login timing differs for unknown usernames (Info)

`POST /api/login` returns 401 immediately for an unknown username,
while a known one costs a full Argon2id verification (~180 ms). The
passkey flow already equalizes its *responses* (identical shape, dummy
allowCredentials) but still saves one DB read for unknown names.

*Impact.* Username enumeration through timing. On a private instance
with open registration disabled-by-default (inactive accounts) this is
a minor signal.

*Recommendation.* One dummy `verify_password` against a fixed hash on
the unknown-user path (or accept and document - F11 already exposes
the same signal by design).

### F11 - Registration answers "username already taken" (Info, accepted)

`POST /api/register` returns 409 with the name. Account enumeration is
inherent to any service where the first account becomes admin and the
rest need activation; documented behaviour, kept for usability.

### F12 - SQLite runs with `synchronous = NORMAL` (Info, accepted)

`db/mod.rs` opens with WAL and `synchronous = NORMAL`: a hard power
loss can cost the most recent transactions, never the whole database.
Right trade-off for an interactive file service; operators who care
back the directory up with the service stopped (or via
`sqlite3 fxcloud.db .backup`), never by copying files under WAL.

### F13 - The login password crosses one redirect via sessionStorage (Info, accepted)

`login.js::carrySecretAcrossRedirect` writes the password into
`sessionStorage` only when the account's keys are wrapped under the
login password (DECISION 3 default), for the length of one navigation;
`fxenc.js` deletes it on first read. Separate passphrases are never
carried. This is the documented exception to "key material never
touches storage" (DECISION 7) and it makes F2's CSP more valuable: any
future XSS becomes a key-theft primitive on such accounts.

### F14 - Basic-auth verdict cache keyed by `DefaultHasher` (Info, accepted)

`auth/mod.rs::basic_cache_key` hashes username+password with the
non-cryptographic `DefaultHasher`. The code documents why this is safe:
a cache hit still has to match the stored Argon2id hash of the account,
and reaching a hit at all requires a credential pair that already
verified once within the TTL. Keys never leave the map unverified.

## What is already solid

The review found the following working as intended; they are listed so
future changes know which properties to preserve.

**Authentication and sessions**

* Argon2id at 64 MiB / t=3 / p=1 for new login hashes - five times the
  crate default and above OWASP's minimum; parameters travel inside the
  hash, so old accounts keep verifying.
* Session tokens: 32 bytes from `OsRng`, hex-encoded, opaque, stored
  server-side with an expiry; expired sessions are ignored on read and
  purged hourly. Cookies are `HttpOnly; SameSite=Lax; Path=/` with
  `Secure` on a knob, which - together with the JSON-only API (any
  form-encoded POST gets 415) - closes CSRF without tokens.
* `AuthUser` re-checks the account on **every** request, so
  deactivating a user cuts access immediately, open sessions included.
  `AdminUser` layers `is_admin` on the same path (403, not 401).
* Passkeys (WebAuthn) are implemented carefully end to end:
  challenges are 32 random bytes, single-use, kind-bound (a login
  challenge cannot register a device) with a 5-minute TTL; clientData
  is compared on type, challenge, exact origin and `crossOrigin`;
  rpId-hash, user-presence and user-verification flags are required;
  the COSE key must be EC2/P-256/ES256 with valid points; `packed`
  accepts only self-attestation with a real ECDSA verify and rejects
  `x5c`; assertions pin `userHandle` to the account and enforce
  signature-counter clone detection. Registration requires an active
  session; login responses cannot enumerate accounts or devices.
* The first account on a fresh instance is the only self-activating
  one (active + admin); every later registration starts inactive.
* The admin dialog cannot deactivate its own caller and cannot leave
  the instance without an active administrator.

**Authorization**

* One central read check (`db/file.rs::readable_entry`) used by the
  JSON routes, the blob reader and the ZIP builder: owner, or a
  covering share (nearest shared ancestor) granting `PERM_READ`, never
  under trash. Writes go through `update_target`/`create_target` with
  the exact permission bit (UPDATE/CREATE/DELETE), and creates land in
  the *tree owner's* ownership when inside a share.
* Shares can only be created by the row's owner
  (`db/share.rs::create_share` filters on `owner_id`); a grantee cannot
  re-share regardless of the `PERM_SHARE` bit. Revoke works for either
  side. One share per (source, grantee); the mount name is uniquified
  in the grantee's root.
* WebDAV authenticates every method with the same Basic verification
  (60s verdict cache, deactivated accounts answered 403), resolves
  paths through the same share-aware `resolve_path`, and MOVE/COPY
  check UPDATE on the source and CREATE at the destination; moving
  across owners is refused and keyed rows keep their key-domain guard.
* Trash is a wall: trashed subtrees are invisible to listing, read,
  write and delete for everyone including the owner until restored;
  purge cascades blobs.
* `PUT /api/files/content` refuses to overwrite encrypted bytes with
  plaintext (and vice versa) and re-encrypts only through the FXE1
  magic check.

**Cryptography (client-side)**

* Content: AES-256-GCM per 4 MiB chunk, per-file random nonce base in
  the header with the chunk index folded in, keys wrapped under parent
  folder keys with AAD domain separation bound to row id and version.
* Account keys: Argon2id floor enforced **server-side** on setup and
  rewrap (`enforce_kdf_floor`, unit-tested from both sides), HKDF-SHA-
  256 with fixed labels, ECIES (X25519 first, P-256 fallback) for share
  envelopes, fingerprints as SHA-256 over the published key blob with
  trust-on-first-use caching (hashes only - no key material in
  localStorage anywhere).
* The server is storage-only by construction: keys are write-through
  opaque blobs, `GET /api/keys/<username>` needs a session, setup is
  idempotent for the same payload and 409 for a different one, and
  share envelopes are size-capped and opaque.

**Input handling, injection, XSS**

* Every SQL statement is parameterized; `format!` is only used to
  splice in compile-time column lists.
* File names are validated (`.`/`..`/separators/control characters
  refused); blob paths are built from numeric ids and timestamps on the
  server, never from client input; the embedded-asset route serves only
  compile-time keys, so there is no filesystem traversal anywhere.
* Uploads are size-capped per request, MIME is server-sniffed from
  bytes (`infer` + text heuristic) with the client's claim only as
  fallback, and encrypted uploads are forced to `mime = NULL` /
  `application/octet-stream` on the way out.
* Previews of browser-renderable files are served `inline` but with
  `Content-Security-Policy: sandbox` and `nosniff`, so an uploaded HTML
  or SVG file cannot script. Downloads are `attachment` + RFC 5987
  names + `nosniff`.
* The frontend escapes first everywhere it builds HTML: `escapeHtml()`
  wraps every user-controlled fragment (names, usernames, badges), and
  the Markdown renderer escapes the source *before* applying any rule
  and allows only `http(s)://`, `/` and `#` in links and images.

**Operations**

* Error responses never leak internals (5xx become a fixed string; the
  detail goes to the journal). Permission failures distinguish only
  what a user can act on.
* The installer refuses to run without root, sanity-checks the
  download, probes versions under `timeout`, keeps a `.bak` for
  rollback, never touches the data directory, and writes a hardened
  unit (NoNewPrivileges, ProtectSystem=strict, ReadWritePaths on the
  data dir, RestrictSUIDSGID, LockPersonality, a `nologin` system
  user). On update it leaves the operator's unit alone.
* The Docker image runs as a non-root user, keeps state in `/data`,
  and has a health check. CI permissions are least-privilege
  (`contents: read` on PRs, `write` only for the tag-triggered release)
  and there is no `pull_request_target` anywhere.
* Dependencies: no known advisories (RustSec, 211 crates); the crypto
  primitives are the platform's (WebCrypto in the browser, `argon2`/
  `p256`/`sha2`/`ciborium` on the server), not hand-rolled.

## Coverage and limitations

* Reviewed: every route in `src/web/routes/`, `webdav.rs`,
  `auth/mod.rs`, `webauthn.rs`, `web/state.rs`, the DB layer
  (`db/*.rs`), `files/mod.rs`, the frontend auth/crypto flows
  (`fxcrypto.js`, `fxenc.js`, `login.js`, `webauthn-client.js`, the
  `app.js` HTML-building and session paths), `install.sh`, `Dockerfile`,
  both workflows.
* Not covered: formal verification of the crypto design (ENCRYPTION.md
  documents the decisions; this audit checked the implementation
  against it), fuzzing of the WebDAV and multipart parsers, a browser
  matrix test of the WebAuthn paths, and third-party JavaScript (there
  is none - all assets are embedded and self-hosted).
* A single audit is a snapshot. The suite pins the security-critical
  behaviours (origin refusals with their journal fields, the KDF floor
  from both sides, session expiry, share permission matrices, the
  sandbox header); every finding fixed here should arrive with its own
  pin.

## Suggested order of work

1. ~~F2 (security headers)~~ - done in v0.0.29.
2. ~~F5 (key-record replace rule)~~ - done in v0.0.30.
3. ~~F3 (invalidate sessions on password change / admin reset)~~ - done
   in v0.0.31.
4. ~~F1 (rate limiting)~~ - done in v0.0.32.
5. ~~F4 (session TTL default, rotation, management UI)~~ - done in
   v0.0.33.
6. ~~F7 (release checksums)~~ - done (CI + installer, no server change;
   in effect with the next tagged release).
7. F6, F8, F10 - small hardening items.
