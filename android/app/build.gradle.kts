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
        targetSdk = 35
        versionCode = 2
        versionName = "0.2.0-s2"
        ndk {
            abiFilters += listOf("arm64-v8a")
        }
    }

    buildFeatures {
        compose = true
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
