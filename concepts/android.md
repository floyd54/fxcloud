# The native Android app (phase 7)

The app takes the browser tab's role: same REST API, same server, no
server change - but keys held on the device, store distribution, and
the device integrations a web page cannot get (hardware-backed key
storage, eventually the share sheet and Credential Manager). The
responsive web UI stays the zero-install path and keeps being verified
on real devices first; this note is about the native one.

The load-bearing constraint comes from phase 5: **one implementation of
the format**. The app must not grow a third copy of the crypto - it
calls the same Rust core the browser's vectors pin, through JNI.

## Architecture

```
android/                 Kotlin + Gradle (wrapper; only a JDK is needed)
  app/                   the UI, the HTTP client, the flow layer
crates/fxjni             JNI glue: Kotlin `external fun`s -> fxcffi
crates/fxcffi            the C ABI (already shipped, already tested)
crates/fxcrypto          the core: containers, keys, envelopes, names
```

- **One shared object.** `crates/fxjni` builds a `cdylib`
  (`libfxcloud.so`) for `aarch64-linux-android` (and `x86_64` for the
  emulator). It wraps **fxcffi**, not fxcrypto directly: the app surface
  stays exactly the C ABI that `ffi_vectors.rs`, the C smoke test and
  `fxcffi.h` already pin, so "what an app may call" has one definition
  and one test suite.
- **JNI rules.** Every entry copies bytes in (Kotlin `ByteArray` ->
  slice), calls through, copies the result out and releases the C buffer
  with `fx_free` - no pointer ever escapes into Kotlin. The i32 codes
  become Kotlin exceptions (`FxException(code, message)`), panics stay
  caught inside `fxcffi` (`FX_ERR_PANIC`). `JNIEnv` is per call, never
  cached across threads; long work (Argon2id, whole-file encrypt) runs
  off the main thread and the result is posted back.
- **The flow layer is Kotlin.** Walking a tree, re-keying, wrapping
  names, sealing an envelope: HTTP and crypto interleaved, exactly like
  `fxenc.js` does it in the browser. The *primitives and records* are
  Rust (never re-implemented); the *orchestration* is per platform, with
  the invariants spelled out where they matter (re-key: wrap before the
  flag goes up; names: URL-safe base64, two-phase create; envelopes:
  `shareEnvelopeAad` byte for byte).
- **The server never renders documents.** It stores and ships bytes;
  PDFs render in the browser, images in the platform engines, and no
  server process ever feeds an uploaded file to a rendering library.
  Document-processing CVEs therefore have no path in: Ghostscript,
  ImageMagick and poppler appear neither in the binary's dependency
  tree nor on the host nor in the office image (checked for
  CVE-2026-125396, the November 2026 `-dSAFER` escape, on 2026-11-23;
  if rendering is ever added, Ghostscript starts at 10.08.0).

## Pinning the app to the same bytes

The read side does not need new trust: the JUnit tests on the **host**
build of `libfxcloud.so` replay the very same fixtures the browser and
the C ABI already answer - `fx1-vectors.json` (13 cases),
`fx-keys-vectors.json` (27 cases, envelopes included). A Kotlin
`fingerprint()` that disagrees with the golden file fails CI exactly
like the Rust twin does. Flow-level behaviour that vectors cannot reach
(cancel walks, partial re-keys) is covered by the same rules the web
side follows: idempotent steps, `failed[]` instead of half-states, and
documented order.

## Keys and unlock

- The passphrase is typed, never stored; Argon2id runs in Rust (native,
  no WASM) with the same stored parameters the web uses.
- After unlock the session material (ARK, root key, private key) lives
  in process memory only - same as the browser tab, DECISION 7.
- **Auto-unlock** mirrors the web's device blob, strengthened: the
  device key is generated **inside the Android Keystore** (TEE/StrongBox
  when available, therefore non-exportable), wraps the ARK, and the blob
  sits in app-private storage - the browser keeps that blob in
  `localStorage`, the Keystore is the honest upgrade of the same idea.
  This needs the device-blob pair exposed on `fxcffi`
  (`createDeviceBlob`/`openDeviceBlob` exist in `fxcrypto.js` but not
  yet in the C ABI) - a small, vector-covered addition.
- Optional later: gate the Keystore release behind `BiometricPrompt`.

## Network

Identical REST surface and the same session cookie the browser gets;
the server cannot tell the difference and needs no change (the
key-blindness rules apply unchanged). No WebDAV (pointless on a phone),
no office engine (it is a browser thing - open such files in the
browser), public links mintable but v1 read of them stays web-side.

## v1 scope (for confirmation)

In: sign-in (password), unlock/recovery, file tree with names-at-rest
decryption, upload/download/preview, rename/move/create, versions,
trash, quotas readout, settings basics (display name, theme, password),
shares with envelopes and fingerprints, recovery-key show/rotate.

Out for v1: passkey registration (sign-in via Android Credential
Manager landed - the passkey section below; creating devices stays
web), groups and key
distribution (v1: group folders are web-administered), office, WebDAV,
public-link management, admin dialog (web only).

## Build and CI

- Toolchain on a Linux box: JDK17, Android command-line tools (sdkmanager
  for platform, build-tools, NDK, platform-tools), `rustup target add
  aarch64-linux-android x86_64-linux-android`, `cargo install cargo-ndk`.
  Roughly 2-4 GB; the Gradle wrapper downloads Gradle itself.
- `android/` pins AGP/Kotlin versions in the wrapper; debug builds are
  sideloaded onto a device (`adb install`), release builds are signed
  with a key kept outside the repo.
- CI: a job next to `test` installs the NDK, builds the `.so` for both
  Android targets, runs the **host** JUnit vector tests, then
  `gradlew assembleDebug` and uploads the APK as an artifact. No
  emulator in CI v1 (Keystore/instrumented tests are a documented
  manual pass).

## Decisions

| # | Question | Decision |
|---|----------|----------|
| A1 | Platform | Android first (this box can build it); iOS is parked, not dead: GitHub's macOS runners can build and sign it later without a local Mac, which needs the Apple account and a decision, not hardware today |
| A2 | UI | Jetpack Compose, `minSdk26` (8.0) - Keystore AES-GCM needs23+,26 is the practical floor for a2026 install base |
| A3 | Crypto boundary | one Rust core; `fxjni` wraps `fxcffi`, so the app may call exactly the surface the C ABI tests already pin; no primitive is ever re-implemented in Kotlin |
| A4 | Flows | Kotlin orchestrates (HTTP + one-line crypto calls), invariants documented per flow; the read side is pinned by the same golden vectors through JNI |
| A5 | Key storage | passphrase never stored; session memory-only; auto-unlock = Keystore-wrapped device key (hardware-backed upgrade of the web's localStorage blob) |
| A6 | Server | unchanged; the app is another client of the same API and cookies |
| A7 | Repo | monorepo: `android/` beside `crates/`, one CI workflow, one release train |

## Slices

| Slice | Exit criterion |
|-------|----------------|
| S1 toolchain + skeleton | JDK/SDK/NDK installed, `cargo-ndk` builds `libfxcloud.so`, `crates/fxjni` exposes a smoke call (fingerprint), the Kotlin project loads it, `gradlew assembleDebug` produces an APK here and in CI, host JUnit replays one golden file through JNI |
| S2 auth + listing | login against a live instance, tree listing with breadcrumb, names-at-rest decrypted through the FFI, dark/light theming |
| S3 crypto flows | unlock (passphrase + recovery), download->decrypt->preview, upload->encrypt, envelope seal/open for shares |
| S4 shares + device | share dialog with fingerprints, revoke, re-key/rotate entry points as they make sense on a phone, Keystore auto-unlock (+ the fxcffi device-blob pair) |
| S5 polish + store | row actions behind a per-row ⋮ menu (share, copy, move, delete) with long-press multi-select and a selection bar, creating folders and files from the path bar, versions, trash, settings parity (incl. hidden dot-entries behind a path-bar toggle and a settings switch), the header collapsed to the web's shape (trash as an icon, the rest - settings, help, sign out - behind the name in a user menu; help renders the server's guide in a script-less WebView), signing, Play listing ($25) |

Status: S1 shipped (on-device pass done). S2 on the device: sign-in,
one-event unlock, tree with path bar, back gesture and header logout
confirmed by the user. S3: primitives, preview and upload confirmed on
the device; S3d (recovery pane, envelope-opened mounts) built, device
pass pending. S4 built (share dialog + revoke, Keystore auto-unlock,
rotate + reseal), device pass pending. S5 built (papierkorb,
settings, versions, per-row menu + multi-select, create folder/file)
plus the light-blue light-mode canvas and the feature-graphic login
hero - shipped together as v0.4.2 (versionCode 6, for the Play
closed track). Play: closed testing is live - screenshots, listing and Data
Safety forms are in, and the user installed the build from the Play
Store (2026-11-21). Text and markdown edit in the app now (source,
markdown toolbar, rendered pane, save through `PUT /files/content`
with the web's key rules - shipped as v0.4.3, versionCode 7).
Production is gated by Google's rule for new
personal accounts: 12 testers continuously opted in for 14 days,
then a review of at most 7 days. The counter tracks tester opt-in,
not builds: uploads during the test do not reset it, but a tester
who opts out restarts that tester's clock - so recruit with margin
(14-16), not exactly 12. The $25 listing is the user's personal
account; the upload key lives in CI secrets (keystore in
`/root/fxcloud-signing`). The BOM stays at `2026.06.01`
because newer ones demand an unreleased `compileSdk 37` (see
`android/README.md`).

## S3 design (crypto flows)

Four flows in four sub-slices; every crypto step is a call into the
`fxcffi` C ABI (the one the vectors pin) and every request shape
mirrors the web twin (`app.js` / `fxenc.js`).

| Sub-slice | Contents |
|-----------|----------|
| S3a primitives | JNI: `encryptBytes`/`decryptBytes` (FXE1, bound to the file id - a row move fails decryption, as on the web), `unlockWithRecovery` (same packed session as S2), `shareEnvelopeAad`/`eciesOpen`/`eciesSeal`. Golden pins: `fx1-vectors.json` (read side - the write side is the JS roundtrip's), `recovery_open`, `ecies_open`, `ecies_seal` (error cases; success = seal->open roundtrip, the envelope carries an ephemeral key). |
| S3b preview | file tap -> `GET /api/files/download?id=` -> content key (`Chain.keyFor` + `unwrapChild` on the row's `enc_key`) -> `decryptBytes` -> render. v1 renders image, text and PDF (the platform's `PdfRenderer`,15 pages max); video/audio/html say so instead of pretending. Plaintext rows preview straight with the server's mime, encrypted rows decide by extension because the server only ever answers `octet-stream`. Whole file into memory - streaming/range is deliberately later. The
image view swipes: sideways steps through the folder's gallery (the
web's arrow buttons as a gesture - tree order, previewables only,
stops at the ends), down closes it; the ← button and the system back
stay as the other two exits. Text and markdown open read-only first, **Edit** swaps the preview for an editor: monospace source, a markdown toolbar (bold/italic/headings/lists/quote/link/code inserted at the selection), a rendered pane for `.md`/`.markdown` (the web's `mdToHtml` ported line for line, its vectors generated from the JS; open in source - the pane is one tap away), save through the web's own `PUT /api/files/content` (`putContent`): an encrypted row re-encrypts under the *same* file key so the history keeps opening, a plaintext row under a keyed folder is promoted with `history=drop` like the web's zone write, and every save makes the server pin the old text as a version - a read-only sharee meets the pinned403. |
| S3c upload | `POST /api/files/file` (random temp name under a `names_enc` folder, then `rename` to the id-bound blob - N3/N5), fresh file key, wrap under the destination folder's key (`PUT /api/files/key` gives a recordless folder one first, mirror `ensureChainKey`), `encryptBytes`, `PUT /api/files/content?id=&enc=1&key=`. A plaintext account takes the same path without `enc`. One file at a time first; the folder upload then walks a picked tree (`OpenDocumentTree` + `DocumentsContract`, no extra dependency), creates the folders on the way (they inherit `names_enc`) and runs every file through the same flow. |
| S3d recovery + share envelopes | recovery pane on the passphrase screen (32-byte key typed as hex -> `unlockWithRecovery`, packed session exactly as S2); incoming share envelopes open with the packed session's private key (`eciesOpen` + `share_envelope_aad`) so mounts show real names and their subtree keys instead of S2's `(encrypted)` placeholders; `eciesSeal` lands the primitive S4's share dialog uses. |

Rules carried over: one undecryptable row shows the placeholder and
never takes a listing or preview down (S2's rule); nothing key-shaped
is ever written to prefs or logs (DECISION 7).

## S4 design (shares + device)

Three sub-slices; the crypto primitives already shipped in S3a/S3d
(`eciesSeal/Open`, `shareEnvelopeAad`, `wrap/unwrap`, the packed
session).

| Sub-slice | Contents |
|-----------|----------|
| S4a share dialog | Long-press a row -> share screen: grantee picker (`GET /api/users`), fingerprint in the web's 8-8-8-8 format (`GET /api/keys/{u}`) with TOFU (first use confirms, a change is spelled out as the risk it is; the hashes live in prefs like the web's `peerfp` - a hash of a published key opens nothing), the five permission checkboxes (READ/UPDATE/CREATE/DELETE/SHARE, all on = 31). Per item one envelope: folders get `ensureChainKey` + `keySubtree` first (legacy records re-bound to their parent - a record that already opens there is left alone, same end state), the sealed value is the row's key under `shareEnvelopeAad(id, grantee)`; a name-flagged row's display label wraps under the same pair (N4, url-safe like the web's `b64url`). `POST /api/shares/batch` with one item, outgoing list (`GET /api/shares/outgoing?file_id=`), revoke (`DELETE /api/shares/{id}`). Plaintext rows share without an envelope; a no-key account gets the web's warning instead of silence. |
| S4b device auto-unlock | The packed session grows an ark tail: `root(32) \|\| u32 pkcs8Len \|\| pkcs8 \|\| u32 arkLen \|\| ark` (root/pkcs8 positions unchanged, every reader updated). After an unlock with the server's `auto_unlock` switch on, store `{v:1, deviceKeyEnc, wrappedArk}` per account: a random device key wrapped by the Android Keystore (hardware-backed - the web's localStorage upgraded), the ARK under it with `fx1:device-ark:v1`. On start the blob opens the session without a prompt (Keystore decrypt -> `unwrap` -> `sessionFromArk`); anything absent, stale or tampered falls back to the passphrase pane, and the switch off deletes the blob (the server flag is the truth). |
| S4c rotate | The web's rotate on a phone: for an encrypted file the owner rotates - download, decrypt under the current key, fresh key, encrypt, `PUT /files/content?enc=1&key=&history=drop` (old history drops with the old key), then `resealOutgoing`: every outgoing share gets the new key sealed to its grantee (`GET /keys/{u}` per grantee -> `eciesSeal` -> `PUT /shares/{id}`), so nobody's envelope goes stale. Entry point where it makes sense on a phone: the preview bar. |

## Passkey login (app)

**Status: built in v0.4.4, removed again.** The provider side could
not be cracked from here: Bitwarden refuses despite fresh, valid
Google DAL fetches (its issue #6164 class), and Google's own path
had no app-visible storage on the test device ("this device" keys
stay browser-visible only, and the creation sheet offered no account
target). The web keeps passkeys fully; the app signs in with
password - plus fingerprint and auto-unlock for encrypted accounts.
The record below stays for operators and a future re-attempt: the
app did exactly this:

The app signed in with the phone's passkeys through the platform's
Credential Manager (`androidx.credentials` 1.6.0), speaking the
*web's own ceremony*:

1. `POST /api/passkeys/login/start {username}` - the answer is
   already the `publicKey` JSON the prompt takes verbatim (challenge,
   rpId, allowCredentials, userVerification).
2. `CredentialManager.getCredential(PublicKeyCredentialOption)` ->
   `authenticationResponseJSON`, posted back as `{credential}` - the
   standard WebAuthn shape `LoginCredentialJson` already deserializes
   (unknown fields ignored, exactly like the browser's `toJSON()`).
3. The finish endpoint mints the session cookie like the password
   door; `finishLogin` continues unchanged (an empty password falls
   into the passphrase step, which is where a passkey user belongs).

Two server pieces make the native half possible:

- **Origin.** A native assertion carries
  `clientData.origin = android:apk-key-hash:<sha256>` - assetlinks
  authorizes the app for the rpId but never rewrites the origin.
  `FXCLOUD_WEBAUTHN_ANDROID_ORIGIN` (comma-separated) lists the
  exact values `login/finish` accepts beside the derived https
  origin; unset (the default) changes nothing for the web.
- **Asset links.** `GET /.well-known/assetlinks.json` serves
  `$FXCLOUD_DATA/assetlinks.json` when the operator drops one in
  (package + signing certificates: the debug keystore is committed -
  `android/debug.keystore` - so sideloads and CI's release APK share
  one certificate; Play's app-signing key covers the store build).
  Google Password Manager refuses the prompt without it. The layout
  is deliberate: **one statement per fingerprint, Play's classic key
  first** - some verifiers (Bitwarden goes through Google's DAL API)
  read only the first entry, so ordering is part of the contract.
- **The provider maze (documented, not just endured).** Bitwarden's
  Android app verifies the calling app through **Google's DAL API** -
  the check Google's own credential-provider docs recommend - even
  against a self-hosted Vaultwarden: it is a lookup about the public
  file, no key material involved. That API fetches without redirects
  and, observed in the wild, with the DNS-root form of the host
  (`https://host.`); a vhost that does not answer the dotted name
  turns a perfect file into "Diese App unterstützt keine Passkeys"
  (Revolut's months-long case: bitwarden/android#6164; Google tracker
  460172858 still open). This deployment: apex serves directly, the
  **dotted host is pending at the outer TLS terminator** (the
  Netbird-fronted VPS in front of this box: `server_name host
  host.;`). The GPM alternative (provider fetches the file itself)
  exists but is rejected here on principle - keys stay in the
  self-hosted Vaultwarden, the proxy line is the path. The
  user-facing story ships in the help guide (USERGUIDE section12,
  en/de), written to be forwarded.

Registration stays in the web. The suite pins the route (file
present -> application/json, absent -> 404) and the origin gate (a
configured app-origin assertion opens a session, an unconfigured one
is refused); `native_app_origin` carries unit tests of its own.

## Login banner

A deployment can put its own notice where every visitor reads it
before signing up:

- `FXCLOUD_LOGIN_BANNER` (server side - editable in the unit, no
  rebuild): rendered into `login.html` as `.server-banner`,
  HTML-escaped (it is configuration, not markup); an empty knob
  renders no element at all. The same text rides
  `GET /api/login-banner` (`{"banner": ...}`, unauthenticated), so
  the app's login form shows it too - fetched debounced after the
  server field settles, because a banner belongs to the server it
  names.
- Suite: the page carries the class and the text, the API serves it;
  `banner_html`'s unit tests pin the escape and the empty case.

## Account erasure (GDPR)

`DELETE /api/admin/users/{id}` (admin only) removes an account and
everything that belongs to it:

- The db refuses while the account still owns group content - a
  group's files are the group's, not one member's to destroy; move or
  delete them first (the same explicit-first spirit as
  `delete_group`).
- Otherwise one transaction: the creator reference out of the groups
  it survives (`created_by = NULL`), then the users row - and
  SQLite's `ON DELETE CASCADE` takes the rest: personal files and
  their versions, sessions, keys, passkeys, shares (both
  directions), public links, memberships, group keys. Rows cascade,
  bytes do not: the blob refs come back and the handler unlinks them
  (`state.files.delete_blobs`), so storage is reclaimed too.
- Guards mirror the demote path: no self-deletion, never the last
  active administrator.
- The web's user-administration dialog gains a "Delete account"
  button behind a confirm; the suite pins the erasure end to end
  (200, dead session, name free again, user and file rows gone,
  self-delete refused).

## Fingerprint unlock

The passphrase pane gains a second way in - the sensor:

- **Enrollment** (settings switch, beside auto-unlock): one
  BiometricPrompt, then the ARK is sealed under an auth-bound
  Android Keystore key (strong biometric for every use on API 30+,
  a 30-second authentication window below) and stored as
  `biodevice.<id>` beside the silent auto-unlock's blob - same
  `{v:1, deviceKeyEnc, wrappedArk}` shape, same downstream adoption
  (openShares included), so nothing past the prompt knows how the
  session arrived.
- **Unlock**: the pane shows "Unlock with fingerprint" whenever a
  blob exists and the sensor authenticates, and asks on its own the
  first time it appears. Success jumps straight to the tree; the
  passphrase field stays visible and always works - the sensor is a
  convenience, never the only door.
- **Invalidation**: enrolling new fingerprints invalidates the
  auth-bound key; the failed attempt drops the blob with a notice to
  unlock by passphrase and set it up again.
- Device-side only, like auto-unlock: the Keystore does not exist
  on the build host, so there is no suite pin and no JVM test -
  the pane's fallback is the guarantee.

## Tests

- Host JUnit: the golden fixtures through JNI (the app's `ffi_vectors`
  twin) - runs in CI without a device.
- `cargo test --workspace` and the shell suite stay green and unchanged
  (this note adds no runtime to the server; the doc-map check in the
  suite requires README to link this file).
- Manual pass per slice on a real device: unlock, upload, share,
  Keystore unlock after reboot.

## Known gaps (encrypted mode)

The server is key-blind by design (A3), so every feature that needs
readable bytes does not exist on encrypted accounts:

- **Office editing** is explicitly disabled for `enc_version > 0`
  (the web's `canOffice`): the WOPI engine would need the plaintext.
  Permanent under this model - office work belongs on a plaintext
  account (what the reference instance's test setup does today).
- **PDF preview**: the web renders PDFs from readable bytes; an
  encrypted row only hands the viewer a container. Solved for the app
  without new dependencies (decrypt -> the platform's built-in
  `PdfRenderer`,15 pages at800px); the web could do the same
  (decrypt -> blob -> iframe, browsers render PDFs natively) and
  still lacks it.
- **WebDAV** on an encrypted account: creates plaintext rows only
  ("DAV has no channel for a key record"), downloads hand out FXE1
  containers, and overwriting an encrypted row is refused (409,
  DECISION 9). Uploads that must be encrypted go through the app or
  the web client; on a plaintext account none of this applies.

## Open questions

- `minSdk26` vs a lower floor (24) - A2 says26, say otherwise if the
  install base needs it.
- v1 scope above: groups remain the cut - passkey sign-in landed (the
  passkey section below); flag groups if the phone needs it first.
