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

Out for v1: passkeys (Android Credential Manager - v2), groups and key
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
| S5 polish + store | versions, trash, settings parity, signing, Play listing ($25) |

Status: S1 shipped (on-device pass done). S2 on the device: sign-in,
one-event unlock, tree with path bar, back gesture and header logout
confirmed by the user. S3: primitives, preview and upload confirmed on
the device; S3d (recovery pane, envelope-opened mounts) built, device
pass pending. The BOM stays at `2026.06.01` because newer ones demand
an unreleased `compileSdk 37` (see `android/README.md`).

## S3 design (crypto flows)

Four flows in four sub-slices; every crypto step is a call into the
`fxcffi` C ABI (the one the vectors pin) and every request shape
mirrors the web twin (`app.js` / `fxenc.js`).

| Sub-slice | Contents |
|-----------|----------|
| S3a primitives | JNI: `encryptBytes`/`decryptBytes` (FXE1, bound to the file id - a row move fails decryption, as on the web), `unlockWithRecovery` (same packed session as S2), `shareEnvelopeAad`/`eciesOpen`/`eciesSeal`. Golden pins: `fx1-vectors.json` (read side - the write side is the JS roundtrip's), `recovery_open`, `ecies_open`, `ecies_seal` (error cases; success = seal->open roundtrip, the envelope carries an ephemeral key). |
| S3b preview | file tap -> `GET /api/files/download?id=` -> content key (`Chain.keyFor` + `unwrapChild` on the row's `enc_key`) -> `decryptBytes` -> render. v1 renders image and text; the web's other `PREVIEW_EXT` kinds (video/audio/pdf/html) say so instead of pretending. Plaintext rows preview straight with the server's mime, encrypted rows decide by extension because the server only ever answers `octet-stream`. Whole file into memory - streaming/range is deliberately later. |
| S3c upload | `POST /api/files/file` (random temp name under a `names_enc` folder, then `rename` to the id-bound blob - N3/N5), fresh file key, wrap under the destination folder's key (`PUT /api/files/key` gives a recordless folder one first, mirror `ensureChainKey`), `encryptBytes`, `PUT /api/files/content?id=&enc=1&key=`. A plaintext account takes the same path without `enc`. v1 = one file at a time; folder trees come later. |
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

## Tests

- Host JUnit: the golden fixtures through JNI (the app's `ffi_vectors`
  twin) - runs in CI without a device.
- `cargo test --workspace` and the shell suite stay green and unchanged
  (this note adds no runtime to the server; the doc-map check in the
  suite requires README to link this file).
- Manual pass per slice on a real device: unlock, upload, share,
  Keystore unlock after reboot.

## Open questions

- `minSdk26` vs a lower floor (24) - A2 says26, say otherwise if the
  install base needs it.
- v1 scope above: groups and passkeys are the two biggest cuts - flag
  either if the phone needs them first.
- Play account and signing key: who owns the $25 listing and where the
  upload key lives (password manager vs CI secret).
