# Concept: public links (anonymous shares) (approved)

Status: **approved** 2026-10-31, implementation in progress. One amendment from
review: the expiry model is no longer a plain fixed date -- by default a link now
expires only after N days **without use** (rolling window); a fixed deadline
("exactly 30 days after creation, used or not") is an explicit override
(sections 3, 8.3, 12.5).

## 1. Goal and non-goals

Goal: an owner can mint a **bearer link** (Dropbox style) that any anonymous visitor
can use without an fxcloud account, scoped to exactly one entry, with a permission
preset and an expiry date. Covers the "send a stranger a file / collect files from
strangers" use case that user-to-user shares cannot serve.

Non-goals for v1:

- No encrypted (E2EE) entries behind a link. v1 is plaintext-only; encrypted links
  are phase 2 (section 5) and deliberately deferred.
- No password protection on links (belongs to phase 2, where it wraps the key).
- No anonymous ZIP downloads, no anonymous previews (section 6 explains why).
- No link statistics beyond a counter, no visitor accounts, no link branding.
- No admin browsing of other users' links (self-hosted, single tenant; abuse is
  handled by revoke + the instance being private).

## 2. What it builds on (current state)

- Permission masks exist and are reusable (`src/sharing.rs`): PERM_READ=1,
  PERM_UPDATE=2, PERM_CREATE=4, PERM_DELETE=8, PERM_SHARE=16, `grants()`,
  `normalize()`. Public links reuse them verbatim (section 4).
- The `shares` table cannot host public links: `grantee_id` is `NOT NULL` with an FK
  to `users`, and `UNIQUE(source_id, grantee_id)` presumes a named grantee
  (`migrations/002_shares.sql:5-18`). Public links get their own table, like
  `group_keys` did in `017_groups.sql` (precedent for "second table next to shares").
- Random-token precedents: `generate_token()` 32 bytes OsRng (`src/db/session.rs:187`),
  `sessions.sid` backfilled with `lower(hex(randomblob(16)))` (`013_sessions_meta.sql:24`),
  WebAuthn challenges as base64url (`src/webauthn.rs:68-80`).
- Rate limiting is in-memory, per socket peer IP, never trusts X-Forwarded-For
  (`src/web/state.rs:61-99, 243-343`); `rate_limited()` maps to 429 + Retry-After
  (`src/error.rs:114`). Public routes add their own gates (section 8).
- Security-header middleware exists and is per-route overridable
  (`src/web/mod.rs:66-90`); the preview route already sets `CSP: sandbox`
  (`src/web/routes/files.rs:845`).
- Trash is a soft delete via `deleted_at` (`src/db/file.rs:543+`), swept on an
  interval (`src/main.rs:125-149`). Visitor deletes reuse it.
- Public-route precedent: the two `passkeys/login/*` handlers carry no `AuthUser`
  (`src/web/mod.rs:257-258`) and API.md marks them `**Public.**`.
- `ENCRYPTION.md` NG3 lists "anonymous access / public links" as a v1 non-goal; this
  concept supersedes NG3 for plaintext entries only (section 5).

## 3. Data model (migration `018_public_links.sql`)

```sql
CREATE TABLE IF NOT EXISTS public_links (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    token_hash      TEXT    NOT NULL UNIQUE,   -- sha256 hex of the bearer token
    source_id       INTEGER NOT NULL REFERENCES files(id)   ON DELETE CASCADE,
    owner_id        INTEGER NOT NULL REFERENCES users(id)   ON DELETE CASCADE,
    permissions     INTEGER NOT NULL,          -- PERM_* mask, PERM_SHARE never set
    label           TEXT,                      -- owner's note, shown in their overview
    expiry_mode     TEXT    NOT NULL DEFAULT 'rolling',  -- 'rolling' | 'fixed' | 'never'
    expires_in_days INTEGER,                   -- window (rolling) / lifetime (fixed); NULL iff 'never'
    created_at      TEXT    NOT NULL,
    expires_at      TEXT,                      -- effective deadline; NULL iff 'never'
    last_access_at  TEXT,
    download_count  INTEGER NOT NULL DEFAULT 0
);
CREATE INDEX IF NOT EXISTS idx_public_links_owner  ON public_links(owner_id);
CREATE INDEX IF NOT EXISTS idx_public_links_source ON public_links(source_id);
```

- **Expiry semantics per mode** (the one place to get this wrong):
  - `rolling` (default): `expires_at` = `last_activity + expires_in_days`. Every
    successful (2xx) visitor operation slides it forward ("nur verlaengern, nie
    verkuerzen" - the new value is always `now + window`, and `now` only grows, so
    it cannot move backwards). The link dies only after `expires_in_days` days
    **without any use**.
  - `fixed`: `expires_at` = `created_at + expires_in_days`, set once at insert and
    never touched again - "verfaellt nach genau 30 Tagen" regardless of traffic.
  - `never`: `expires_at` NULL; no deadline ever.
  - **Ordering invariant**: the expiry check runs **before** the touch. An expired
    link is never resurrected by a visit (rolling links included: coming back after
    the window lapsed must yield 410, not restart the window). Owner operations
    (list, revoke) never count as use and never touch.

- The **token itself is never stored**; the server keeps `sha256(token)` and looks
  links up by hash. A leaked DB dump or backup therefore yields no working links
  (unlike a raw-token column). Lookup is a single indexed equality on 256 bits of
  entropy.
- Token: 32 random bytes, base64url without padding (43 chars), generated
  client-side? No - server-side, via the existing OsRng helper, returned exactly once
  at creation.
- `source_id ... ON DELETE CASCADE`: deleting the file deletes the link. Moving the
  file does **not** break it - resolution is by id, not path, so links survive
  renames and moves (unlike a path-based scheme).
- Multiple links per source are allowed (different labels, rights, expiry); no
  `UNIQUE(source_id)`.
- Plaintext-only enforcement is a **write-time** rule: creating a link on an entry
  with `enc_version > 0` is refused with 409 (section 5). No schema column needed.
- Migration guard: none required (pure `CREATE TABLE IF NOT EXISTS`, like 001);
  registered in `src/db/mod.rs` after `017_groups`.

## 4. Permission model (the three presets)

The owner picks one of three presets; they map onto the existing mask, and the
server enforces them with the same `grants()` helper the user-to-user shares use:

| Preset     | Mask (bits)              | Visitor may                                  |
| ---------- | ------------------------ | -------------------------------------------- |
| `read`     | READ (1)                 | list + download                              |
| `add`      | CREATE (4)               | upload files/folders, **see and download nothing** |
| `full`     | READ UPDATE CREATE DELETE (15) | list, download, upload, delete          |

- `add` without READ is what makes the Dropbox-File-Request behavior fall out for
  free: the listing route requires READ, so an `add`-link visitor gets 403 on list
  and download, and nothing about the folder's contents is ever disclosed (not even
  names). Uploaded files land under the shared source, owned by the link owner.
- PERM_SHARE (16) is **never** grantable on a link: an anonymous visitor cannot mint
  further links. `normalize()` already drops unknown bits; routes additionally refuse
  a mask containing PERM_SHARE at creation time.
- One source rule, applied like `db/share.rs:41-66` does for shares: the source must
  be a personal entry of the caller. Group-owned rows (`owner_group_id` set) are
  refused in v1 with 403 (groups have their own audience logic; revisit later).

## 5. E2EE stance (v1 plaintext-only, honestly stated)

fxcloud is end-to-end encrypted; a public link in v1 works only for entries stored
plaintext (`enc_version = 0`). This is a deliberate, documented trade, not a flaw:

- The **server never decrypts anything** - it does not have to: for plaintext rows
  there is nothing to decrypt. v1 links disclose nothing the server could not
  already read at rest (which is why the threat model of section 8 is about *who
  holds the link*, not about the server).
- **Mixed folders:** a linked folder lists and serves only its plaintext children.
  Entries with `enc_version > 0` are filtered out of the visitor listing and refuse
  download (409). They are not merely "undownloadable", they are **invisible** -
  their names never reach the visitor. The owner's dialog shows the count of hidden
  entries before creating the link so the decision is informed.
- **Encrypted source refused at creation:** `POST /api/links` on an `enc_version > 0`
  entry returns 409 with a stable error code, and the UI disables the control with
  the explanation (phase 2 will enable it).
- Phase 2 (deferred, sketched in section 13): the content key travels in the URL
  **fragment** (`/s/<token>#<key>`), which browsers never send to the server; the
  visitor page decrypts in-browser. E2EE then holds for public links too, and an
  optional password (Argon2id) wraps the key so the link alone is insufficient.
  v1's schema and routes are shaped so phase 2 is an additive change (same table,
  same routes, key material only ever in the fragment).

## 6. Public routes (visitor surface, no session)

All under `/api/public/{token}/...`, plus the page `/s/{token}`. No `AuthUser`
extractor anywhere in this module; authorization comes from the token alone.

| Route | Rights | Behavior |
| ----- | ------ | -------- |
| `GET /s/{token}` | - | static visitor page (section 7) |
| `GET /api/public/{token}/meta` | - | `{name, is_dir, permissions, permission_names, expires_at}` |
| `GET /api/public/{token}/list` | READ | plaintext children of the source (folders recurse by id) |
| `GET /api/public/{token}/download?id=` | READ | blob as `attachment`, id must be inside the shared subtree |
| `POST /api/public/{token}/upload` | CREATE | multipart, `owner_id` = link owner, parent = source (or chosen subdir with READ) |
| `DELETE /api/public/{token}/entry?id=` | DELETE | soft delete into the **owner's** trash |

- Subtree containment: every `?id=` is checked to be the source or a descendant
  (same parent-walk with the 64-hop cap as `covering_share`, `db/share.rs:267`).
  A visitor can never reach a sibling or anything above the source.
- Downloads always `Content-Disposition: attachment` + `nosniff` + forced
  `application/octet-stream`. **No inline rendering in v1**: a stranger-uploaded
  `evil.html` served from our origin would be stored XSS / a phishing page under the
  instance's domain. Skipping anonymous previews deletes that whole risk class; the
  app's own preview already relies on sandbox, but the public surface does not get
  the benefit of the doubt.
- ZIP: not in v1 (the existing zip job machinery is session-bound). Folder links
  download per file.
- Visitor responses add, per-route override of the global middleware:
  `Referrer-Policy: no-referrer` (the token lives in the URL path - it must never
  leak via Referer), `Cache-Control: no-store`, `X-Robots-Tag: noindex`.

## 7. Owner routes, UI, and the visitor page

Owner side (authenticated, under `/api/links`):

| Route | Behavior |
| ----- | -------- |
| `POST /api/links` | `{file_id, permissions, expiry_mode?, expires_in_days?, label?}` -> `{token}` **once**, plus the link record (`expiry_mode` default `rolling`; `expires_in_days` default 30, ignored+NULL for `never`) |
| `GET /api/links` | owner's overview: records only (no tokens - they are not recoverable), with `download_count`/`last_access_at` |
| `DELETE /api/links/{id}` | revoke (owner only) |

- UI: the share dialog (`#share-modal`) gains a second section "Public link":
  preset select (Read / Add / Full, default Read), expiry select (values below,
  **default: "30 days without use"**), optional label, Create. Expiry options:
  `rolling:30` "expires after 30 days without use" (default), `rolling:90`
  "after 90 days without use", `fixed:30` "exactly 30 days after creation",
  `fixed:90` "exactly 90 days after creation", `never` "never expires" - the
  select value maps 1:1 to `expiry_mode` + `expires_in_days`. On success the full
  URL is shown once with a copy button and the note that it cannot be shown
  again. The overview lists active links per file with revoke (and shows the
  effective `expires_at`). Hidden-encrypted-count warning before creating a link
  on a folder.
- Visitor page `/s/{token}`: minimal static page (own JS file, no login, no app
  bundle), reuses `i18n.js`. Shows the entry name, listing and download buttons
  (READ), upload form with progress (CREATE), delete buttons (DELETE). The `api()`
  helper redirects to `/login` on 401 (`app.js:162-183`), so the visitor page uses
  its own tiny fetch wrapper that surfaces errors inline instead.
- All new i18n keys en/de/tlh (x3), counted in the suite's key-count check.
- No WebDAV surface for links (Basic auth only there); noted as non-goal.

## 8. Security (the section that decides this feature)

Threat model: the token **is** the credential (bearer). Anyone holding it has the
preset's rights until expiry or revoke. Everything below either raises the cost of
obtaining a token, limits the blast radius of a leaked one, or keeps the public
surface from harming the instance.

1. **Token entropy**: 32 bytes OsRng, base64url (256 bits). Guessing is infeasible;
   enumeration is not a meaningful attack. Miss responses are uniform.
2. **Stored hashed**: only `sha256(token)` at rest (section 3). DB dump, backup, or
   a shoulder-surfed admin query yields no usable link. Sessions store raw tokens;
   links deliberately do not, because links are shareable secrets that outlive any
   single device.
3. **Expiry by default**: rolling, 30 days of inactivity; a fixed deadline or
   "never" are explicit choices. A forgotten link dies on its own - the main
   real-world leak vector; a *used* link stays alive for as long as it is being
   used, which is the point of a share link and cannot be exploited to prolong a
   link nobody has lost track of (inactivity is what kills it). Expired -> `410
   Gone` (distinct from `404` for unknown tokens: friendly for visitors,
   meaningless as an oracle without the token).
4. **Revoke**: row delete, effective on the next request, no caching anywhere.
   Deleting the file or the owner cascades to the link.
5. **Rate limits** (new gates in `state.rs`, same in-memory per-peer-IP pattern,
   X-Forwarded-For still never trusted): a tight *miss* budget (bad/expired token,
   e.g. 20/min) and a generous *hit* budget; plus a per-link upload budget (per IP,
   hourly) so a scraped link cannot fill the owner's quota in a loop. All 429 +
   Retry-After via the existing error mapping.
6. **Quota**: anonymous uploads count against the **owner's** quota (files are owned
   by them); `max_upload_bytes` applies unchanged. A hostile visitor can therefore
   consume quota up to the budget-and-quota ceiling; revoke stops it, and the
   overview's counters make it visible.
7. **No CSRF surface**: the public routes authenticate by path token, not by cookie,
   so ambient-credential CSRF does not apply; an attacker who can drive a victim's
   browser to the link already holds the token themselves. No CSRF tokens needed,
   and the routes must keep ignoring cookies entirely (no `AuthUser` fallback).
8. **XSS / content abuse**: downloads are attachment-only, octet-stream, nosniff;
   no inline preview, no anonymous HTML rendering on the instance's origin
   (section 6). The visitor page is a static asset served with the existing CSP.
9. **No token leakage**: `Referrer-Policy: no-referrer` + `no-store` + `noindex`
   on the public surface; the token appears in no log line (routes log ids and
   outcomes, never the path); the owner overview never re-echoes tokens.
10. **Containment**: subtree check on every `?id=` (section 6); `PERM_SHARE` never
    grantable; personal entries only; group rows refused.
11. **Traffic amplification**: a link holder can trigger repeated downloads of the
    owner's file - acceptable (same as any public file host), bounded by the hit
    budget; `download_count` gives the owner a signal.
12. **Integrity of the record**: all writes (create/revoke/upload/delete) go through
    the DB layer with explicit owner/token checks like the existing share code;
    no string-built SQL; token compared only via indexed hash equality.

Residual risks, stated openly: a leaked link is readable by anyone until expiry or
revoke (inherent to bearer links - mitigated by default expiry, hashed storage, and
phase 2 adding password-wrapped keys); the server sees visitor IPs (as it does for
every request); plaintext links mean the content was never E2EE to begin with.

## 9. Abuse and operations

- Expired links are removed lazily (on access, before the 410) **and** by a sweep
  hook next to the trash sweep in `src/main.rs` (same interval, cheap indexed scan
  on `expires_at`), so unvisited dead links do not accumulate.
- `last_access_at`/`download_count` update on read traffic **and slide
  `expires_at` forward for rolling links** - one small UPDATE per successful
  visitor operation; fine at self-hosted scale, and the only write-on-read in the
  codebase (state it honestly: a hit on a rolling link extends its life, by
  design).
- No new env vars in v1 (budgets are constants like the existing auth gates);
  revisit if someone needs `FXCLOUD_LINK_*` knobs.
- Observability: tracing on create/revoke/expiry/429, never the token.

## 10. Test strategy

Unit tests (`src/db/link.rs` / `src/web/routes/links.rs`):

- token hash -> lookup roundtrip; unknown token -> None; expired -> treated as gone.
- expiry modes: rolling slides `expires_at` forward on touch (never backwards);
  fixed is never touched; `never` stays NULL; touch on an already-expired link is
  refused (no resurrection).
- permission mapping: each preset grants exactly its documented routes; PERM_SHARE
  in the mask is refused at creation.
- subtree containment: sibling and parent ids refused; deep chain hits the hop cap.
- encrypted source refused (409); encrypted child filtered from listing and from
  download; `add` preset refused on list/download with 403.
- cascade: deleting the source deletes the link; moving the source keeps it.
- expiry sweep removes rows; lazy expiry returns 410 and removes.

Suite (`tests/suite.sh`, new section "public links"):

- create link per preset; anonymous `meta`/`list`/`download` as visitor (no cookie).
- `add` visitor: upload succeeds, list and download 403, and the folder's existing
  names never appear in any response body.
- `full` visitor: delete -> owner's trash lists it; owner restores.
- revoke -> 404 afterwards; expired link -> 410; unknown token -> 404.
- rolling: successful visitor call moves `expires_at` forward (sqlite3 before/after);
  fixed: successful call leaves `expires_at` untouched; expired rolling link stays
  410 after a visit (not resurrected).
- rate limit: burst of bad tokens -> 429 with Retry-After.
- encrypted file: link creation 409; mixed folder: encrypted child invisible.
- owner overview lists the link with counter; token shown once at creation only.
- visitor page serves 200 without a session; i18n key count bumped (x3).

## 11. Size: **M**

Backend: one migration, `src/db/link.rs` (new, ~250 lines), `src/web/routes/links.rs`
(owner) + `src/web/routes/public.rs` (visitor), two new rate gates in `state.rs`, one
sweep hook in `main.rs`, router entries. Frontend: share-dialog section, visitor page
+ JS, i18n keys x3. Docs: API.md rows + section, ENCRYPTION.md NG3 note, this
concept, USERGUIDE section. No crypto changes, no WebDAV, no key distribution -
which is why this is M and not L (compare: groups was L because of envelopes,
bootstrap, and admin).

## 12. Decisions (summary)

1. New table `public_links`; `shares` stays user-to-user (its NOT NULL grantee FK
   forbids reuse).
2. Token: 32 bytes server-side OsRng, shown once; only `sha256(token)` stored.
3. Three presets mapped onto the existing PERM mask; `add` = CREATE without READ =
   upload-only, disclosure-free; PERM_SHARE never grantable.
4. v1 plaintext-only: encrypted sources refused at creation (409), encrypted children
   invisible in linked folders; documented, not hidden. Phase 2 adds fragment-key
   links.
5. Default expiry: **rolling 30 days of inactivity** (every successful visitor
   call slides the deadline forward); `fixed` = hard deadline from creation,
   `never` explicit; expired = 410, unknown = 404; lazy cleanup + sweep; an
   expired link is never resurrected by a visit.
6. Visitor deletes go to the owner's trash; uploads count against the owner's quota;
   files are owned by the link owner.
7. No anonymous inline preview, no anonymous ZIP, attachment-only downloads.
8. Bearer-token threat model section 8: hashed at rest, per-IP rate gates,
   no-referrer/no-store/noindex, subtree containment, cookies ignored.
9. Personal entries only in v1; group rows refused (403).
10. Links survive move/rename (id-based), die with the file or the owner (cascade).

## 13. Deferred (phase 2+, not scheduled)

- **Encrypted links**: key material in the URL fragment (`#<key>`), browser-side
  decrypt, server still blind; optional Argon2id password wrapping the key (link
  alone insufficient); `history.replaceState` after reading the fragment.
- Anonymous ZIP (reuse the zip job machinery with a token-scoped job).
- Password-only protection for plaintext links (server-side gate; low value without
  key wrapping - hence phase 2 together with E2EE links).
- Per-link download caps, link statistics, "notify on first use".
- Group-owned sources (needs the group permission story, not just a flag).
