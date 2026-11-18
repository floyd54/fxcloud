// Root build: plugin versions only (concepts/android.md A2/S1).
// AGP9 pairs with Gradle9 and JDK17+ (the box runs JDK21) and applies
// Kotlin itself - the separate kotlin.android plugin stopped existing
// with AGP9 (kotl.in/gradle/agp-built-in-kotlin).
plugins {
    id("com.android.application") version "9.5.1" apply false
}
