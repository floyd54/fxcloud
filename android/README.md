# fxcloud Android app (S1 skeleton)

The native client of `concepts/android.md`. S1 proves the boundary:
`libfxcloud.so` (built from `crates/fxjni`) answers a golden fingerprint
through JNI, on the host in JUnit and on the device in `MainActivity`.

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
