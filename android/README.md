# fxcloud Android app (S2: sign-in + tree)

The native client of `concepts/android.md`. S2 state: the app signs in
against a live instance with the same JSON login and `fxcloud_session`
cookie as the browser, unlocks encrypted accounts through
`FxCore.unlock` (Argon2id + ARK chain in Rust), lists the tree with its
breadcrumb and decrypts names-at-rest through `FxCore.unwrapChild` -
the golden fixtures replay through JNI on the host (JUnit) and in CI.

Versions, deliberately not the newest: `compileSdk = 36` with the
Compose BOM `2026.06.01` (Compose 1.11.x). The BOMs from August on
require `compileSdk 37`, whose SDK package is not released on the
stable channel yet; `minSdk 26` is unaffected either way.

## Build the .so

From the repository root (JDK17+, Android SDK/NDK, `cargo-ndk` - see
concepts/android.md "Build and CI"; on a machine where the SDK lives
outside the default location, export it first, e.g.
`export ANDROID_HOME=/opt/android-sdk`):

```sh
cargo build -p fxjni                                   # host, for JUnit
cargo ndk -t arm64-v8a -P 26 build -p fxjni --release \
  -o android/app/src/main/jniLibs                      # device
```

## Build the APK

```sh
cd android && ./gradlew assembleDebug
# app/build/outputs/apk/debug/app-debug.apk - sideload with adb install
```

## Test the boundary on the host

```sh
cargo build -p fxjni && cd android && ./gradlew test
```

The JUnit tests replay `tests/fixtures/fx-keys-vectors.json` through
the JNI layer - the same committed bytes the browser, the Rust twin and
the C ABI already answer.
