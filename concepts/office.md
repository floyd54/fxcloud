# Concept: in-browser office documents (OnlyOffice / Euro-Office / Collabora)

Status: **decided** 2026-11-02 - WOPI host confirmed, engine left to the
operator at deploy time, feature gated behind `FXCLOUD_OFFICE_URL`.
Nothing is implemented yet; section 14 holds what is still open.

## 1. Goal and non-goals

Goal: open and edit Office files (docx, xlsx, pptx, odt, ods, odp) in the
browser, saved back into fxcloud under the same rules as every other
write (permissions, quota, versions, trash).

Honest baseline first: WebDAV already lets a desktop app (LibreOffice,
Word) edit these files with full fidelity. What is missing is the
click-file-edit-in-browser path - for devices without a desktop setup,
for sharees who never configure WebDAV, and for the "someone sent me a
docx" case.

Non-goals (v1):

- No editing of encrypted (E2EE) rows: plaintext only, the same boundary
  WebDAV already draws (ENCRYPTION.md 7).
- No anonymous editing through public links.
- No new formats: csv/tsv stay in the built-in text editor, PDF keeps the
  native preview.
- fxcloud does not gain an HTTP client: all office traffic comes *in*
  (section 4).
- No bundled engine: the office server is an optional sidecar the
  operator runs themselves.

## 2. What it builds on (current state)

- Office files are inert in the web UI today: `extension_type` and
  `previewKind` know no Office extension, so a click does nothing and the
  row menu offers Download (concepts/preview.md).
- The write machinery a save must reuse already exists and is shared by
  the built-in editor and WebDAV: `stream_body_to_temp` (flat memory,
  S1), `update_file_meta` (PERM_UPDATE + tree owner + quota gate -> 507),
  `pin_content_as_version` (outgoing bytes become a version), the
  extension/mime decision. A new writer that calls the same sequence
  cannot diverge from the others (src/web/routes/files.rs,
  src/webdav.rs).
- Version bounds are per user: `version_keep_n` (default 20) and
  `version_keep_days` (default 180), applied on save and by the sweep.
- The app CSP is one static const (`src/web/mod.rs`, Audit F2) with
  `frame-src 'self' blob:` - an editor iframe from another origin does
  not fit it today, and the suite pins the header.
- No HTTP client crate and no JWT/HMAC crate in Cargo.toml; `sha2` and
  `base64` are already dependencies.

## 3. The engines (facts, 2026-11)

| | OnlyOffice Docs (Community) | Euro-Office | Collabora CODE |
|---|---|---|---|
| Origin | Ascensio, Docs 9.3, mature | fork by Nextcloud + IONOS, first stable release 2026 | Collabora, LibreOffice-based |
| License | AGPLv3 + Section 7 branding terms | AGPLv3, Section 7 terms removed (public dispute with OnlyOffice; reported settled with source/brand notices added) | LibreOffice core (MPL 2.0) + Collabora code; CODE is the free build |
| Protocol | Docs JS API (native), WOPI since 6.4 | same codebase -> same protocols (confirm in the spike) | WOPI native |
| Resources (Docker) | official: 1 core / 4 GB RAM / 40 GB disk below 100 users | same lineage | ~1.3 GB RAM idle (operator reports), guidance 1 GB + 100 MB/user |
| Fidelity | strongest OOXML | same engine as OnlyOffice | strongest ODF, weaker OOXML |

Two consequences for fxcloud:

1. **fxcloud must speak a protocol, not a product.** The OnlyOffice
   family offers both protocols, WOPI is Collabora's native one.
   Choosing WOPI as the fxcloud-side surface keeps all three engines
   swappable by changing one URL - the OnlyOffice-vs-Euro-Office question
   becomes an operator decision at deploy time, not a code decision.
2. **Neither engine's license touches fxcloud.** fxcloud stays MIT: it
   talks HTTP to a separate process it does not link, modify or
   redistribute. What the operator runs is their affair - with one trap
   (section 7).

## 4. Why WOPI and not the Docs callback API

Docs API (the Nextcloud route): fxcloud passes `document.url` +
`callbackUrl` + `document.key` + a JWT; the engine downloads the file
from fxcloud, and after a save hands fxcloud **a URL to download the new
bytes from**. fxcloud would need an HTTP client (TLS included, if the
engine sits behind HTTPS) and would have to pin that URL to the
configured engine origin (SSRF hygiene).

WOPI: the engine calls CheckFileInfo/GetFile/PutFile **on fxcloud**; the
saved bytes arrive as a request body fxcloud already knows how to stream
(`stream_body_to_temp`). No outbound request, no client crate, one less
trust boundary. Costs: some Docs-API niceties (e.g. forcesave) have
historically been missing or late in WOPI, and the iframe/api.js wiring
differs per engine - both are spike items (section 11).

Provisional decision: **WOPI host** as the fxcloud surface; the Docs API
only if the spike shows a hard blocker.

*Confirmed by the operator 2026-11-02: the WOPI path is the one to
build. The engine choice stays a deploy-time URL (section 13, #2).*

## 5. Proposed architecture (WOPI host)

New routes, all token-authenticated, all absent when `FXCLOUD_OFFICE_URL`
is unset:

```text
GET  /api/office/start?id=<fileId>  -> {url}   mints the iframe URL and
                                               access token; the secret
                                               never reaches the browser
GET  /wopi/files/<id>               -> CheckFileInfo JSON
GET  /wopi/files/<id>/content       -> streamed bytes (open_blob)
POST /wopi/files/<id>               -> PutFile: body -> standard save
```

- **Token**: HMAC-SHA256 over (file id, user id, permissions, opened-at,
  expiry) with `FXCLOUD_OFFICE_SECRET`; stateless - no schema, no
  migration. Short-lived (hours) and re-checked against *live*
  permissions on every call, so a revoked share cannot keep writing.
- **CheckFileInfo** carries what the editor needs: BaseFileName, Size,
  MimeType (`mime_guess`), Version (`modified_at`, so the engine
  re-fetches after any WebDAV or built-in-editor write),
  LastModifiedTime, UserId, UserFriendlyName, `UserCanWrite` =
  PERM_UPDATE (a read-only share opens the viewer), `SupportsLocks:
  false` in v1 (spike item).
- **PutFile** re-runs the permission check, the quota gate (507 travels
  back as a failed save), the trash and encryption checks (404/409), then
  the standard save sequence. The body streams through
  `stream_body_to_temp`: flat memory, exactly like an upload.
- **Frontend**: office extensions gain a preview kind. Feature off ->
  nothing changes (row inert, Download in the menu). Feature on -> a
  click opens a full-screen overlay with the engine's iframe; close
  refreshes the row (size, modified_at). txt/md/csv stay in the built-in
  editor.
- **Config**: `FXCLOUD_OFFICE_URL` (browser-side editor base; unset =
  feature off), `FXCLOUD_OFFICE_SECRET` (token key), optional
  `FXCLOUD_OFFICE_WOPI_BASE` for the URL the *engine* uses to reach
  fxcloud (Docker bridge vs public URL; defaults to `FXCLOUD_ORIGIN`).

## 6. Version history: the save-volume problem

The engine saves on every pause (about 10 s of inactivity), so one
editing session can produce a dozen versions and evict useful history
through `version_keep_n = 20`. Two rules:

- **(a) pin every replacement** - today's invariant for every writer,
  simplest, but a chatty session shreds its own history.
- **(b) pin per session** - pin when the outgoing content was written
  *before this session opened* (the minted token carries opened-at) and
  skip the intermediate saves. Pre-session state and cross-mechanism
  writes (WebDAV, built-in editor) always land in history;
  intra-session intermediates do not.

Recommendation: **(b)**, falling back to (a) if the engine turns out to
hide its session boundaries. Quota is unaffected either way - versions
count, just fewer of them.

## 7. Security

- **New trust boundary.** The engine parses hostile Office files for a
  living and sees the plaintext of everything it opens. It is the
  operator's own sidecar (same trust class as the fxcloud process), but a
  much bigger attack surface: keep it updated, containerize it, expose it
  only through the proxy, give it memory limits.
- **Reads are token-gated, never session-gated**: the engine has no
  cookie. Tokens bind file + user + expiry, are checked against live
  permissions on every call, and an unknown or expired token answers 404
  - never a hint that the id exists.
- **The AGPL trap**: never vendor the engine's JavaScript into fxcloud -
  load the iframe/api.js from the engine's origin at runtime. Linking or
  redistributing AGPL assets into an MIT repository is the one way this
  feature could taint fxcloud; talking HTTP to it does not.
- **CSP**: feature on -> `frame-src` gains the engine origin
  (`script-src` too only on the api.js route), built once at startup
  from config. Feature off -> the header stays byte-for-byte what the
  suite pins today.
- **Proxy**: the engine needs websockets (Upgrade headers) and a body
  limit of at least `FXCLOUD_MAX_UPLOAD_MB` - PutFile is an upload by
  another name.
- **E2EE**: plaintext rows only (409 on encrypted), the boundary WebDAV
  already draws; the UI says so where it offers the button.

## 8. Deployment impact (the honest bill)

| | today | with office editing |
|---|---|---|
| Processes | one binary | +1 container (engine sizing below) |
| Disk | a few MB | image ~2 GB + engine cache (OnlyOffice guidance: 40 GB class) |
| Proxy | plain reverse proxy | + websocket upgrade, bigger body limit |
| fxcloud env | - | +2..3 variables, off by default |
| Schema | - | none (stateless tokens, no migration) |
| Single-binary claim | unchanged | unchanged *for fxcloud itself*; README gains one honest sentence that office editing needs an optional sidecar |

**The sizing rule to publish (README / INSTALL.md):**

- **Office editing needs about 4 GB of RAM for the engine container** on
  top of fxcloud itself: Collabora CODE idles around 1.3 GB (plus ~100 MB
  per concurrent user); the OnlyOffice-class engines are sized 4 GB RAM /
  40 GB disk by their vendor guidance. Budget **+4 GB** and all three
  engines fit.
- **A 32 GB instance runs this without noticing** - the engine is a
  rounding error there, and fxcloud's own footprint stays the single
  small binary it is today.
- **A 1-2 GB VPS runs without Office, and that is a supported
  configuration, not a missing feature.** The documented answer for that
  box is the WebDAV mount: `rclone`, a Windows network drive or the
  Finder connects the same tree to LibreOffice/Word, and editing office
  files over WebDAV works today with full fidelity (concepts/files.md,
  USERGUIDE section 14). Office integration is an *addition* for
  instances with RAM to spare, never a requirement.

None of this exists unless `FXCLOUD_OFFICE_URL` is set: no routes, no CSP
change, no UI change, no cost.

## 9. i18n and UX strings

Every new string exists in en/de/tlh (the suite's parity walk pins it):
"Open in office editor", "Editing read-only", "Save failed: quota
exceeded", "Encrypted files cannot be edited here", "Close editor",
"Office server not configured". The iframe itself carries the engine's
own language - pass the fxcloud language (en/de; tlh falls back to en) as
the engine's language parameter.

## 10. Testing

- **In the suite the engine is curl.** The WOPI endpoints are plain
  REST: CheckFileInfo fields, GetFile bytes, a PutFile that appends and
  asserts the content changed and the old bytes became a version, quota
  full -> 507, missing/expired/foreign token -> 404, encrypted row ->
  409, read-only token -> `UserCanWrite: false` and a refused PutFile,
  feature off -> 404 on every route, CSP unchanged when off and widened
  when on, i18n keys x3. No Docker in CI, no real engine in the suite.
- **The real engine is a manual smoke test** (documented in INSTALL.md):
  run one container, open, type, close, verify the bytes landed and the
  version appeared.
- The suite count in ARCHITECTURE.md moves with the new checks.

## 11. Phases

- **Phase 0 - spike (about half a day, throwaway):** run the Collabora
  image and the OnlyOffice image against a 50-line WOPI stub; confirm
  embedding, save round-trip, `SupportsLocks: false`,
  websocket-through-proxy, and whether the Euro-Office image behaves
  identically. This decides the engine question with facts instead of
  opinions. **Needs a Docker-capable host** - the fxcloud development
  machine has no Docker, so the spike runs on the 32 GB instance (or any
  box with the containers), not here.
- **Phase 1 (v1):** the WOPI host of section 5, plaintext single-file
  editing, overlay UI, i18n, suite section, docs (README bullet,
  INSTALL.md section, API.md, USERGUIDE).
- **Phase 2:** locks and co-editing etiquette, read-only preview for
  sharees, install.sh optionally configuring the sidecar.
- **Phase 3 (maybe):** public-link editing, encrypted-copy editing,
  engine-side conversion for preview-only rendering.

## 12. Size: **L**

Protocol module + config-built CSP + overlay UI + i18n x3 + suite section
+ three documents; no migration; plus the phase-0 spike before any of it.

## 13. Decisions (summary)

| # | Question | Decision |
|---|---|---|
| 1 | Protocol | **WOPI host** - all traffic inbound, no HTTP client, engines swappable; Docs API only if the spike blocks |
| 2 | Engine | **operator's choice at deploy time** (OnlyOffice / Euro-Office / Collabora) - fxcloud binds to a URL, not a product |
| 3 | Feature gate | `FXCLOUD_OFFICE_URL` unset = no routes, no CSP change, no UI change |
| 4 | Encrypted rows | plaintext only (409), same boundary as WebDAV |
| 5 | AGPL assets | never vendored - iframe/api.js loaded from the engine origin at runtime |
| 6 | Version volume | pin per session (b), not per autosave - section 6 |
| 7 | Locks (v1) | `SupportsLocks: false`; in-memory locks are a phase-2 item |
| 8 | Public links | out of scope for v1 |
| 9 | RAM / who gets it | **+4 GB budget for the engine** (all three fit); a 32 GB box runs it unnoticed, a 1-2 GB VPS runs **without** Office - WebDAV mount + native tools is the supported answer there, not a missing feature - section 8 |

## 14. Open questions (for the operator)

1. Engine preference now, or decide after the phase-0 spike? The spike
   is cheap and makes this a config value either way. (RAM is settled:
   budget +4 GB, section 8 / decision 9.)
2. Is read-only *preview* in the browser (for sharees, viewer mode)
   wanted in v1? Same machinery, half the UX work.
3. Version rule (a) or (b) in section 6 - (b) is the recommendation.
