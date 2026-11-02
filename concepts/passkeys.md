# Concept: passkeys (WebAuthn)

Status: **implemented** (migration `012_webauthn_credentials`; the
rate-limited challenge door and the origin warning followed in v0.0.32
and v0.0.34).

## 1. Goal

A second way in, not a second secret: a passkey signs a user in with a
PIN or biometric instead of a password. The account's password, its
sessions, its shares and the encryption hierarchy of ENCRYPTION.md are
untouched by them. The private half never leaves the authenticator; the
server stores the attested public key, the signature counter and a
label.

## 2. Ceremony rules

- **Username-first.** `login/start` takes the name and answers with an
  `allowCredentials` list; discoverable-credential-only flows are not
  part of the endpoints. An unknown name, an account without passkeys
  and a real account get byte-for-byte identical responses - the first
  two a single random, unusable entry instead of an empty list, so the
  dialog never reveals who has an account.
- **Challenges** are 32 random bytes held in memory for five minutes
  and single-use: redemption removes the entry (a replay is `401`), and
  the ceremony kind is re-checked, so a registration challenge cannot
  open a session and a login challenge cannot register a device. The
  map is capped at 256 pending ceremonies (429 past it); a restart
  clears pending ceremonies and the user simply starts again.
- **Algorithms:** ES256 on P-256 only, `userVerification: "required"`
  (UP and UV flags checked) - a PIN or biometric gesture, not just a
  touch. Attestation is requested as `none`; `packed` without a
  certificate chain is accepted, a chain (`x5c`) is refused.
- **Counter (clone detection):** a nonzero counter must strictly
  advance (`stored > 0 && new > 0 && new <= stored` is `400`);
  authenticators that never count (many platform passkeys stay at 0)
  are exempt.
- **Account state is checked last**, exactly like the password flow: a
  valid passkey on a deactivated account answers `403`, and only after
  the credential itself verified.

## 3. Origin and rpId

- The origin comes from `FXCLOUD_ORIGIN` when set, otherwise from
  `X-Forwarded-Proto` (or `FXCLOUD_SECURE_COOKIE`) plus `Host`. The
  browser sends `Origin` on every ceremony POST and it must equal that
  value - a mismatch is `400` with a pointer at `FXCLOUD_ORIGIN`,
  *before* a challenge is spent.
- Behind a reverse proxy that rewrites `Host` or terminates TLS without
  forwarding the scheme the derived value is wrong, which is why a
  public deployment needs both HTTPS and the exact `FXCLOUD_ORIGIN`.
  A listen address beyond loopback without the knob logs a WARN at
  startup naming the consequence (Audit.md F8).
- The rpId is the origin's host without port; the rpId hash inside
  `authenticatorData` must match it, so a credential minted for another
  domain is `400`.

## 4. Device management

- `GET /api/me/passkeys` lists the account's devices (`id`, `label`,
  `created_at`, `last_used_at`, `transports`); `PATCH` renames one
  (1-100 chars), `DELETE` removes one. Ids are scoped to the owner: a
  foreign or unknown id is `404`, never a hint that it exists.
- Removing the **last** passkey is allowed on purpose - the password
  keeps working, and cutting off a lost device must never be blocked
  by a policy question.
- A passkey sign-in carries no password, so the encryption pane asks
  for the storage passphrase itself when it needs one (ENCRYPTION.md
  5.7).

## 5. Requirements on a deployment

- A **secure context**: browsers expose `navigator.credentials` only
  over HTTPS or on `localhost`; over plain HTTP on a LAN address the
  UI tells you the browser blocks them.
- The passkey is bound to the origin and hostname it was created
  under, so the instance's public URL must be announced with
  `FXCLOUD_ORIGIN` (see USERGUIDE section 13 for a worked example).

## 6. Where it lives

- Code: `src/webauthn.rs`, `src/db/passkey.rs`,
  `src/web/routes/passkeys.rs`.
- API: [API.md](../API.md) - Passkeys section (ceremony endpoints,
  error matrix).
- User side: [USERGUIDE.md](../USERGUIDE.md) section 12.
- Tests: `tests/suite.sh` section "passkeys (WebAuthn)" plus the
  challenge-door pins in the hardening batch.
