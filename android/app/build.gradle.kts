// The S1 skeleton (concepts/android.md): no dependencies beyond the
// framework - the crypto arrives as libfxcloud.so from cargo-ndk, not
// from a Maven artifact. The real UI (Compose) starts with S2. AGP9
// applies Kotlin itself (kotl.in/gradle/agp-built-in-kotlin).
plugins {
    id("com.android.application")
}

android {
    namespace = "de.frischux.fxcloud"
    compileSdk = 35

    defaultConfig {
        applicationId = "de.frischux.fxcloud"
        minSdk = 26
        targetSdk = 35
        versionCode = 1
        versionName = "0.1.0-s1"
        // One ABI in S1 (spec A1: the devices we build for); x86_64 for
        // an emulator joins when there is one to run.
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    packaging {
        jniLibs {
            // cargo-ndk's -o drops the fxcffi cdylib next to ours too;
            // libfxcloud.so links it statically (NEEDED: libc, libdl
            // only), so the second .so would be dead weight.
            excludes += "**/libfxcffi.so"
        }
    }
}

dependencies {
    // Host-side golden-vector tests only (concepts/android.md A4); the
    // device build has no dependencies beyond the framework.
    testImplementation("junit:junit:4.13.2")
}

// The .so is produced by `cargo ndk -t arm64-v8a -P26 build -p fxjni -o
// app/src/main/jniLibs` (see android/README.md), not by this build.
