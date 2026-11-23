// S2: the real screens (concepts/android.md). The XML frame from S1
// stays - it is the shape that proved itself on the device - and the
// Compose view fills what is below the header.
plugins {
    id("com.android.application")
    // Kotlin 2.x requires the Compose compiler as its own plugin; the
    // version tracks the Kotlin toolchain AGP 9 ships (2.2.10).
    id("org.jetbrains.kotlin.plugin.compose") version "2.2.10"
}

android {
    namespace = "de.frischux.fxcloud"
    compileSdk = 36

    defaultConfig {
        applicationId = "de.frischux.fxcloud"
        minSdk = 26
        targetSdk = 36
        versionCode = 7
        versionName = "0.4.3"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildFeatures {
        compose = true
    }

    signingConfigs {
        create("play") {
            // CI hands in the upload key from the repository secrets
            // (PLAY_KEYSTORE_*); without them - local builds, the debug
            // workflow - storeFile stays null and release falls back to
            // the debug key, so nothing ever fails to build.
            val path = System.getenv("PLAY_KEYSTORE_FILE")
            if (!path.isNullOrBlank()) {
                storeFile = file(path)
                storePassword = System.getenv("PLAY_KEYSTORE_PASSWORD")
                keyAlias = System.getenv("PLAY_KEY_ALIAS")
                keyPassword = System.getenv("PLAY_KEY_PASSWORD")
            }
        }
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            signingConfig = signingConfigs.findByName("play")
                ?.takeIf { it.storeFile != null }
                ?: signingConfigs.getByName("debug")
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
    // Compose for the S2 screens (A2); the BOM pins every androidx.compose
    // artifact, activity-compose brings the setContent entry point.
    val composeBom = platform("androidx.compose:compose-bom:2026.06.01")
    implementation(composeBom)
    implementation("androidx.activity:activity-compose:1.13.0")
    implementation("androidx.compose.material3:material3")

    // Host-side golden-vector tests only (concepts/android.md A4); the
    // device build has no dependencies beyond these.
    testImplementation("junit:junit:4.13.2")
    // Reading the committed fixtures on the JVM (android's org.json is
    // not on the host classpath).
    testImplementation("org.json:json:20260814")
}
