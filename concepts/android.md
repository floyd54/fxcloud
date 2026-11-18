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

Status: S1 shipped (on-device pass done). S2 built - JVM vectors and CI
green, device pass pending; the BOM stays at `2026.06.01` because newer
ones demand an unreleased `compileSdk 37` (see `android/README.md`).

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
