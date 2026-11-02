# Concept: accounts and sessions

Status: **implemented** (baseline feature; the session list with the
seven-day sliding window landed in v0.0.33, sign-in rate limiting in
v0.0.32 and v0.0.34).

## 1. Goal

Registration, sign-in and the session behind the HttpOnly cookie, plus
the account settings every user manages for themselves. The first
account on a fresh instance becomes the administrator; every later
account starts inactive.

## 2. Registration and activation

- `POST /api/register`: username at least 3 characters (trimmed and
  lowercased), password at least 8 characters, optional display name
  (defaults to the username). Passwords are hashed with Argon2id.
- The **first account** is activated immediately and carries `is_admin`.
  Every later account answers `202 pending_activation` with no cookie:
  sign-in is `403` with a hint to contact an administrator, WebDAV is
  `403` instead of a password loop, and `GET /api/me` stays `401`.
- `is_active` is checked on every request, so deactivating an account
  cuts its web sessions and WebDAV mounts at once, with no restart.
  Sharing keeps working in both directions - the grantee simply sees
  the share once their account is activated.

## 3. Sessions

- Server-side rows behind an HttpOnly cookie. The TTL is
  `FXCLOUD_SESSION_TTL` (default 604800 = 7 days) and slides while the
  session is in use: any API request carrying the cookie rewrites the
  expiry to now + TTL, at most once per renewal window (a quarter of
  the lifetime, capped at a day), so an active session never dies under
  its user.
- The settings dialog lists every session with the device it was made
  on, `created_at`, `last_seen_at` and a `current` flag. One session
  can be ended by its `sid` handle, or all others at once ("sign out
  everywhere else"). A `sid` is a label, never the token: a foreign id
  answers `404`, never a hint that it exists.
- Changing the password keeps the calling session open and ends every
  other session of the account (v0.0.31).

## 4. Account settings (per user)

- `PUT /api/me`: display name (1-100 chars) and theme (`light` /
  `dark`); `400` when the body would change nothing.
- `PUT /api/me/password`: the current password is asked first, the new
  one must be at least 8 characters.
- The language choice lives only in `localStorage["fxcloud.lang"]` -
  a browser preference, not account data (TRANSLATING.md).

## 5. Administration

- `PUT /api/admin/users/:id` (admin only) flips `is_active`, `is_admin`
  and `quota_bytes`. Refused with `400`: self-deactivation, demoting or
  deactivating the last active administrator, a negative quota.
- `POST /api/admin/users/:id/password` resets a password and hands
  back a one-time generated temporary password (16 alphanumeric
  characters, about 95 bits) for the next sign-in.
- The same switches work directly in the database without a restart;
  USERGUIDE section 9 carries the statements.

## 6. Sign-in hardening

- **Per-account backoff:** after 5 failed sign-ins the name is locked
  for a window that starts at 10 s and doubles up to 300 s; the failure
  count is remembered for an hour, so the next lock is longer than the
  last. An invented name carries the same backoff as a real one - a
  refusal never tells an attacker who has an account.
- **Per-source budgets:** 30 failed sign-ins per minute and source
  address, 10 registrations per 10 minutes. `X-Forwarded-For` is never
  trusted; the socket peer is the key, which keeps a spoofed header
  from aiming the limiter at somebody else.
- **Timing parity:** the unknown-user branch spends one Argon2id
  verification against a fixed dummy hash, so it costs exactly what a
  wrong password costs (Audit.md F10).

## 7. Where it lives

- Code: `src/auth/`, `src/db/user.rs`, `src/db/session.rs`,
  `src/web/routes/auth.rs`, `src/web/routes/admin.rs`,
  `src/web/state.rs` (budgets and backoff).
- API: [API.md](../API.md) - endpoint table, account activation.
- Model: [ARCHITECTURE.md](../ARCHITECTURE.md) - sessions & activation.
- User side: [USERGUIDE.md](../USERGUIDE.md) sections 2, 3, 9, 10.
- Tests: `tests/suite.sh` sections "accounts", "user settings",
  "user administration", "session management" and "authentication rate
  limiting"; unit tests in `src/web/state.rs`.
