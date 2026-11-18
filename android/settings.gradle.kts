// The native Android app (concepts/android.md). One module for now:
// S1 is a skeleton whose only job is to load libfxcloud.so and prove
// the JNI boundary with a golden fingerprint.
pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}
dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        google()
        mavenCentral()
    }
}
rootProject.name = "fxcloud"
include(":app")
