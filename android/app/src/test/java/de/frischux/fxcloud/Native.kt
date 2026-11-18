package de.frischux.fxcloud

import java.io.File

/**
 * Loads the HOST build of libfxcloud.so for the JVM unit tests
 * (concepts/android.md A4). On a device the app loads the Android
 * build through System.loadLibrary in FxCore instead.
 */
object Native {
    fun load() {
        val candidates = listOf(
            "../../target/debug/libfxcloud.so",
            "../target/debug/libfxcloud.so",
            "target/debug/libfxcloud.so"
        )
        val lib = candidates.map(::File).firstOrNull(File::exists)
            ?: error(
                "host libfxcloud.so not found - run `cargo build -p fxjni` " +
                    "from the repository root first"
            )
        System.load(lib.absolutePath)
    }
}
